--! Previous: sha1:b6b182753668bd9f858e44f95d1338c65c0a87be
--! Hash: sha1:ee07180be766df17416e485c20b476f1b75a88c2
--! Message: accounts and auth

--! split: 0040-pg-sessions-table.sql
/*
 * This table is used (only) by `connect-pg-simple` (see `installSession.ts`)
 * to track cookie session information at the webserver (`express`) level if
 * you don't have a redis server. If you're using redis everywhere (including
 * development) then you don't need this table.
 *
 * Do not confuse this with the `app_private.sessions` table.
 */

CREATE TABLE app_private.connect_pg_simple_sessions
(
    sid    varchar   NOT NULL,
    sess   json      NOT NULL,
    expire timestamp NOT NULL
);
ALTER TABLE app_private.connect_pg_simple_sessions
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_private.connect_pg_simple_sessions
    ADD CONSTRAINT session_pkey PRIMARY KEY (sid) NOT DEFERRABLE INITIALLY IMMEDIATE;

--! split: 1000-sessions.sql
/*
 * The sessions table is used to track who is logged in, if there are any
 * restrictions on that session, when it was last active (so we know if it's
 * still valid), etc.
 *
 * In Starter we only have an extremely limited implementation of this, but you
 * could add things like "last_auth_at" to it so that you could track when they
 * last officially authenticated; that way if you have particularly dangerous
 * actions you could require them to log back in to allow them to perform those
 * actions. (GitHub does this when you attempt to change the settings on a
 * repository, for example.)
 *
 * The primary key is a cryptographically secure random uuid; the value of this
 * primary key should be secret, and only shared with the user themself. We
 * currently wrap this session in a webserver-level session (either using
 * redis, or using `connect-pg-simple` which uses the
 * `connect_pg_simple_sessions` table which we defined previously) so that we
 * don't even send the raw session id to the end user, but you might want to
 * consider exposing it for things such as mobile apps or command line
 * utilities that may not want to implement cookies to maintain a cookie
 * session.
 */

CREATE TABLE app_private.sessions
(
    uuid        uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id     uuid        NOT NULL,
    -- You could add access restriction columns here if you want, e.g. for OAuth scopes.
    created_at  timestamptz NOT NULL DEFAULT NOW(),
    last_active timestamptz NOT NULL DEFAULT NOW()
);
ALTER TABLE app_private.sessions
    ENABLE ROW LEVEL SECURITY;

-- To allow us to efficiently see what sessions are open for a particular user.
CREATE INDEX ON app_private.sessions (user_id);

--! split: 1010-session-functions.sql
/*
 * This function is responsible for reading the `jwt.claims.session_id`
 * transaction setting (set from the `pgSettings` function within
 * `installPostGraphile.ts`). Defining this inside a function means we can
 * modify it in future to allow additional ways of defining the session.
 */

-- Note we have this in `app_public` but it doesn't show up in the GraphQL
-- schema because we've used `postgraphile.tags.jsonc` to omit it. We could
-- have put it in app_hidden to get the same effect more easily, but it's often
-- useful to un-omit it to ease debugging auth issues.
CREATE FUNCTION app_public.current_session_id() RETURNS uuid AS
$$
SELECT NULLIF(pg_catalog.CURRENT_SETTING('jwt.claims.session_id', TRUE), '')::uuid;
$$ LANGUAGE sql STABLE;
COMMENT ON FUNCTION app_public.current_session_id() IS
    E'Handy method to get the current session ID.';


/*
 * We can figure out who the current user is by looking up their session in the
 * sessions table using the `current_session_id()` function.
 *
 * A less secure but more performant version of this function might contain only:
 *
 *   select nullif(pg_catalog.current_setting('jwt.claims.user_id', true), '')::uuid;
 *
 * The increased security of this implementation is because even if someone gets
 * the ability to run SQL within this transaction they cannot impersonate
 * another user without knowing their session_id (which should be closely
 * guarded).
 *
 * The below implementation is more secure than simply indicating the user_id
 * directly: even if an SQL injection vulnerability were to allow a user to set
 * their `jwt.claims.session_id` to another value, it would take them many
 * millenia to be able to correctly guess someone else's session id (since it's
 * a cryptographically secure random value that is kept secret). This makes
 * impersonating another user virtually impossible.
 */
CREATE FUNCTION app_public.current_user_id() RETURNS uuid AS
$$
SELECT user_id
FROM app_private.sessions
WHERE uuid = app_public.current_session_id();
$$ LANGUAGE sql STABLE
                SECURITY DEFINER
                SET search_path TO pg_catalog, public, pg_temp;
COMMENT ON FUNCTION app_public.current_user_id() IS
    E'Handy method to get the current user ID for use in RLS policies, etc; in GraphQL, use `currentUser{id}` instead.';

--! split: 1020-users.sql
/*
 * The users table stores (unsurprisingly) the users of our application. You'll
 * notice that it does NOT contain private information such as the user's
 * password or their email address; that's because the users table is seen as
 * public - anyone who can "see" the user can see this information.
 *
 * The author sees `is_admin` and `is_verified` as public information; if you
 * disagree then you should relocate these attributes to another table, such as
 * `user_secrets`.
 */
CREATE TABLE app_public.users
(
    id          uuid PRIMARY KEY     DEFAULT gen_random_uuid(),
    username    citext      NOT NULL UNIQUE CHECK (LENGTH(username) >= 2 AND LENGTH(username) <= 24 AND
                                                   username ~ '^[a-zA-Z]([_]?[a-zA-Z0-9])+$'),
    name        text,
    avatar_url  text CHECK (avatar_url ~ '^https?://[^/]+'),
    is_admin    boolean     NOT NULL DEFAULT FALSE,
    is_verified boolean     NOT NULL DEFAULT FALSE,
    created_at  timestamptz NOT NULL DEFAULT NOW(),
    updated_at  timestamptz NOT NULL DEFAULT NOW()
);
ALTER TABLE app_public.users
    ENABLE ROW LEVEL SECURITY;

-- We couldn't implement this relationship on the sessions table until the users table existed!
ALTER TABLE app_private.sessions
    ADD CONSTRAINT sessions_user_id_fkey
        FOREIGN KEY ("user_id") REFERENCES app_public.users ON DELETE CASCADE;

-- Users are publicly visible, like on GitHub, Twitter, Facebook, Trello, etc.
CREATE POLICY select_all ON app_public.users FOR SELECT USING (TRUE);
-- You can only update yourself.
CREATE POLICY update_self ON app_public.users FOR UPDATE USING (id = app_public.current_user_id());
GRANT SELECT ON app_public.users TO :DATABASE_VISITOR;
-- NOTE: `insert` is not granted, because we'll handle that separately
GRANT UPDATE (username, name, avatar_url) ON app_public.users TO :DATABASE_VISITOR;
-- NOTE: `delete` is not granted, because we require confirmation via request_account_deletion/confirm_account_deletion

COMMENT ON TABLE app_public.users IS
    E'A user who can log in to the application.';

COMMENT ON COLUMN app_public.users.id IS
    E'Unique identifier for the user.';
COMMENT ON COLUMN app_public.users.username IS
    E'Public-facing username (or ''handle'') of the user.';
COMMENT ON COLUMN app_public.users.name IS
    E'Public-facing name (or pseudonym) of the user.';
COMMENT ON COLUMN app_public.users.avatar_url IS
    E'Optional avatar URL.';
COMMENT ON COLUMN app_public.users.is_admin IS
    E'If true, the user has elevated privileges.';

CREATE TRIGGER _100_timestamps
    BEFORE INSERT OR UPDATE
    ON app_public.users
    FOR EACH ROW
EXECUTE PROCEDURE app_private.tg__timestamps();

/**********/

-- Returns the current user; this is a "custom query" function; see:
-- https://www.graphile.org/postgraphile/custom-queries/
-- So this will be queryable via GraphQL as `{ currentUser { ... } }`
CREATE FUNCTION app_public.current_user() RETURNS app_public.users AS
$$
SELECT users.*
FROM app_public.users
WHERE id = app_public.current_user_id();
$$ LANGUAGE sql STABLE;
COMMENT ON FUNCTION app_public.current_user() IS
    E'The currently logged in user (or null if not logged in).';

/**********/

-- The users table contains all the public information, but we need somewhere
-- to store private information. In fact, this data is so private that we don't
-- want the user themselves to be able to see it - things like the bcrypted
-- password hash, timestamps of recent login attempts (to allow us to
-- auto-protect user accounts that are under attack), etc.
CREATE TABLE app_private.user_secrets
(
    user_id                             uuid        NOT NULL PRIMARY KEY REFERENCES app_public.users ON DELETE CASCADE,
    password_hash                       text,
    last_login_at                       timestamptz NOT NULL DEFAULT NOW(),
    failed_password_attempts            int         NOT NULL DEFAULT 0,
    first_failed_password_attempt       timestamptz,
    reset_password_token                text,
    reset_password_token_generated      timestamptz,
    failed_reset_password_attempts      int         NOT NULL DEFAULT 0,
    first_failed_reset_password_attempt timestamptz,
    delete_account_token                text,
    delete_account_token_generated      timestamptz
);
ALTER TABLE app_private.user_secrets
    ENABLE ROW LEVEL SECURITY;
COMMENT ON TABLE app_private.user_secrets IS
    E'The contents of this table should never be visible to the user. Contains data mostly related to authentication.';

/*
 * When we insert into `users` we _always_ want there to be a matching
 * `user_secrets` entry, so we have a trigger to enforce this:
 */
CREATE FUNCTION app_private.tg_user_secrets__insert_with_user() RETURNS trigger AS
$$
BEGIN
    INSERT INTO app_private.user_secrets(user_id) VALUES (new.id);
    RETURN new;
END;
$$ LANGUAGE plpgsql VOLATILE
                    SET search_path TO pg_catalog, public, pg_temp;
CREATE TRIGGER _500_insert_secrets
    AFTER INSERT
    ON app_public.users
    FOR EACH ROW
EXECUTE PROCEDURE app_private.tg_user_secrets__insert_with_user();
COMMENT ON FUNCTION app_private.tg_user_secrets__insert_with_user() IS
    E'Ensures that every user record has an associated user_secret record.';

/*
 * Because you can register with username/password or using OAuth (social
 * login), we need a way to tell the user whether or not they have a
 * password. This is to help the UI display the right interface: change
 * password or set password.
 */
CREATE FUNCTION app_public.users_has_password(u app_public.users) RETURNS boolean AS
$$
SELECT (password_hash IS NOT NULL)
FROM app_private.user_secrets
WHERE user_secrets.user_id = u.id
  AND u.id = app_public.current_user_id();
$$ LANGUAGE sql STABLE
                SECURITY DEFINER
                SET search_path TO pg_catalog, public, pg_temp;

CREATE OR REPLACE FUNCTION app_public.viewer() RETURNS app_public.users AS
$$
SELECT *
FROM app_public.users
WHERE id = app_public.current_user_id();
$$ LANGUAGE sql STABLE;

COMMENT ON FUNCTION app_public.viewer() IS
    E'The currently logged in user (or null if not logged in).';

--! split: 1030-user_emails.sql
/*
 * A user may have more than one email address; this is useful when letting the
 * user change their email so that they can verify the new one before deleting
 * the old one, but is also generally useful as they might want to use
 * different emails to log in versus where to send notifications. Therefore we
 * track user emails in a separate table.
 */
CREATE TABLE app_public.user_emails
(
    id          uuid PRIMARY KEY     DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL DEFAULT app_public.current_user_id() REFERENCES app_public.users ON DELETE CASCADE,
    email       citext      NOT NULL CHECK (email ~ '[^@]+@[^@]+\.[^@]+'),
    is_verified boolean     NOT NULL DEFAULT FALSE,
    is_primary  boolean     NOT NULL DEFAULT FALSE,
    created_at  timestamptz NOT NULL DEFAULT NOW(),
    updated_at  timestamptz NOT NULL DEFAULT NOW(),
    -- Each user can only have an email once.
    CONSTRAINT user_emails_user_id_email_key UNIQUE (user_id, email),
    -- An unverified email cannot be set as the primary email.
    CONSTRAINT user_emails_must_be_verified_to_be_primary CHECK (is_primary IS FALSE OR is_verified IS TRUE)
);
ALTER TABLE app_public.user_emails
    ENABLE ROW LEVEL SECURITY;

-- Once an email is verified, it may only be used by one user. (We can't
-- enforce this before an email is verified otherwise it could be used to
-- prevent a legitimate user from signing up.)
CREATE UNIQUE INDEX uniq_user_emails_verified_email ON app_public.user_emails (email) WHERE (is_verified IS TRUE);
-- Only one primary email per user.
CREATE UNIQUE INDEX uniq_user_emails_primary_email ON app_public.user_emails (user_id) WHERE (is_primary IS TRUE);
-- Allow efficient retrieval of all the emails owned by a particular user.
CREATE INDEX idx_user_emails_user ON app_public.user_emails (user_id);
-- For the user settings page sorting
CREATE INDEX idx_user_emails_primary ON app_public.user_emails (is_primary, user_id);

-- Keep created_at and updated_at up to date.
CREATE TRIGGER _100_timestamps
    BEFORE INSERT OR UPDATE
    ON app_public.user_emails
    FOR EACH ROW
EXECUTE PROCEDURE app_private.tg__timestamps();

-- When an email address is added to a user, notify them (in case their account was compromised).
CREATE TRIGGER _500_audit_added
    AFTER INSERT
    ON app_public.user_emails
    FOR EACH ROW
EXECUTE PROCEDURE app_private.tg__add_audit_job(
        'added_email',
        'user_id',
        'id',
        'email'
    );

-- When an email address is removed from a user, notify them (in case their account was compromised).
CREATE TRIGGER _500_audit_removed
    AFTER DELETE
    ON app_public.user_emails
    FOR EACH ROW
EXECUTE PROCEDURE app_private.tg__add_audit_job(
        'removed_email',
        'user_id',
        'id',
        'email'
    );

-- You can't verify an email address that someone else has already verified. (Email is taken.)
CREATE FUNCTION app_public.tg_user_emails__forbid_if_verified() RETURNS trigger AS
$$
BEGIN
    IF EXISTS(SELECT 1 FROM app_public.user_emails WHERE email = new.email AND is_verified IS TRUE) THEN
        RAISE EXCEPTION 'An account using that email address has already been created.' USING ERRCODE = 'EMTKN';
    END IF;
    RETURN new;
END;
$$ LANGUAGE plpgsql VOLATILE
                    SECURITY DEFINER
                    SET search_path TO pg_catalog, public, pg_temp;
CREATE TRIGGER _200_forbid_existing_email
    BEFORE INSERT
    ON app_public.user_emails
    FOR EACH ROW
EXECUTE PROCEDURE app_public.tg_user_emails__forbid_if_verified();

-- If the email wasn't already verified (e.g. via a social login provider) then
-- queue up the verification email to be sent.
CREATE TRIGGER _900_send_verification_email
    AFTER INSERT
    ON app_public.user_emails
    FOR EACH ROW
    WHEN (new.is_verified IS FALSE)
EXECUTE PROCEDURE app_private.tg__add_job('user_emails__send_verification');

COMMENT ON TABLE app_public.user_emails IS
    E'Information about a user''s email address.';
COMMENT ON COLUMN app_public.user_emails.email IS
    E'The users email address, in `a@b.c` format.';
COMMENT ON COLUMN app_public.user_emails.is_verified IS
    E'True if the user has is_verified their email address (by clicking the link in the email we sent them, or logging in with a social login provider), false otherwise.';

-- Users may only manage their own emails.
CREATE POLICY select_own ON app_public.user_emails FOR SELECT USING (user_id = app_public.current_user_id());
CREATE POLICY insert_own ON app_public.user_emails FOR INSERT WITH CHECK (user_id = app_public.current_user_id());
-- NOTE: we don't allow emails to be updated, instead add a new email and delete the old one.
CREATE POLICY delete_own ON app_public.user_emails FOR DELETE USING (user_id = app_public.current_user_id());

GRANT SELECT ON app_public.user_emails TO :DATABASE_VISITOR;
GRANT INSERT (email) ON app_public.user_emails TO :DATABASE_VISITOR;
-- No update
GRANT DELETE ON app_public.user_emails TO :DATABASE_VISITOR;

-- Prevent deleting the user's last email, otherwise they can't access password reset/etc.
CREATE FUNCTION app_public.tg_user_emails__prevent_delete_last_email() RETURNS trigger AS
$$
BEGIN
    IF EXISTS(
            WITH remaining AS (SELECT user_emails.user_id
                               FROM app_public.user_emails
                                        INNER JOIN deleted
                                                   ON user_emails.user_id = deleted.user_id
                                    -- Don't delete last verified email
                               WHERE (user_emails.is_verified IS TRUE OR NOT EXISTS(
                                       SELECT 1
                                       FROM deleted d2
                                       WHERE d2.user_id = user_emails.user_id
                                         AND d2.is_verified IS TRUE
                                   ))
                               ORDER BY user_emails.id ASC

                                   /*
                                    * Lock this table to prevent race conditions; see:
                                    * https://www.cybertec-postgresql.com/en/triggers-to-enforce-constraints/
                                    */
                                   FOR UPDATE OF user_emails)
            SELECT 1
            FROM app_public.users
            WHERE id IN (SELECT user_id
                         FROM deleted
                         EXCEPT
                         SELECT user_id
                         FROM remaining)
        )
    THEN
        RAISE EXCEPTION 'You must have at least one (verified) email address' USING ERRCODE = 'CDLEA';
    END IF;

    RETURN NULL;
END;
$$
    LANGUAGE plpgsql
-- Security definer is required for 'FOR UPDATE OF' since we don't grant UPDATE privileges.
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp;

-- Note this check runs AFTER the email was deleted. If the user was deleted
-- then their emails will also be deleted (thanks to the foreign key on delete
-- cascade) and this is desirable; we only want to prevent the deletion if
-- the user still exists so we check after the statement completes.
CREATE TRIGGER _500_prevent_delete_last
    AFTER DELETE
    ON app_public.user_emails
    REFERENCING old TABLE AS deleted
    FOR EACH STATEMENT
EXECUTE PROCEDURE app_public.tg_user_emails__prevent_delete_last_email();

/**********/

/*
 * Just like with users and user_secrets, there are secrets for emails that we
 * don't want the user to be able to see - for example the verification token.
 * Like with user_secrets we automatically create a record in this table
 * whenever a record is added to user_emails.
 */
CREATE TABLE app_private.user_email_secrets
(
    user_email_id                uuid PRIMARY KEY REFERENCES app_public.user_emails ON DELETE CASCADE,
    verification_token           text,
    verification_email_sent_at   timestamptz,
    password_reset_email_sent_at timestamptz
);
ALTER TABLE app_private.user_email_secrets
    ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE app_private.user_email_secrets IS
    E'The contents of this table should never be visible to the user. Contains data mostly related to email verification and avoiding spamming users.';
COMMENT ON COLUMN app_private.user_email_secrets.password_reset_email_sent_at IS
    E'We store the time the last password reset was sent to this email to prevent the email getting flooded.';

CREATE FUNCTION app_private.tg_user_email_secrets__insert_with_user_email() RETURNS trigger AS
$$
DECLARE
    v_verification_token text;
BEGIN
    IF new.is_verified IS FALSE THEN
        v_verification_token = ENCODE(gen_random_bytes(7), 'hex');
    END IF;
    INSERT INTO app_private.user_email_secrets(user_email_id, verification_token) VALUES (new.id, v_verification_token);
    RETURN new;
END;
$$ LANGUAGE plpgsql VOLATILE
                    SECURITY DEFINER
                    SET search_path TO pg_catalog, public, pg_temp;
CREATE TRIGGER _500_insert_secrets
    AFTER INSERT
    ON app_public.user_emails
    FOR EACH ROW
EXECUTE PROCEDURE app_private.tg_user_email_secrets__insert_with_user_email();
COMMENT ON FUNCTION app_private.tg_user_email_secrets__insert_with_user_email() IS
    E'Ensures that every user_email record has an associated user_email_secret record.';

/**********/

/*
 * When the user receives the email verification message it will contain the
 * token; this function is responsible for checking the token and marking the
 * email as verified if it matches. Note it is a `SECURITY DEFINER` function,
 * which means it runs with the security of the user that defined the function
 * (which is the database owner) - i.e. it can do anything the database owner
 * can do. This means we have to be very careful what we put in the function,
 * and make sure that it checks that the user is allowed to do what they're
 * trying to do - in this case, we do that check by ensuring the token matches.
 */
CREATE FUNCTION app_public.verify_email(user_email_id uuid, token text) RETURNS boolean AS
$$
BEGIN
    UPDATE app_public.user_emails
    SET is_verified = TRUE,
        is_primary  = is_primary OR NOT EXISTS(
                SELECT 1
                FROM app_public.user_emails other_email
                WHERE other_email.user_id = user_emails.user_id
                  AND other_email.is_primary IS TRUE
            )
    WHERE id = user_email_id
      AND EXISTS(
            SELECT 1
            FROM app_private.user_email_secrets
            WHERE user_email_secrets.user_email_id = user_emails.id
              AND verification_token = token
        );
    RETURN found;
END;
$$ LANGUAGE plpgsql STRICT
                    VOLATILE
                    SECURITY DEFINER
                    SET search_path TO pg_catalog, public, pg_temp;
COMMENT ON FUNCTION app_public.verify_email(user_email_id uuid, token text) IS
    E'Once you have received a verification token for your email, you may call this mutation with that token to make your email verified.';

/*
 * When the users first email address is verified we will mark their account as
 * verified, which can unlock additional features that were gated behind an
 * `isVerified` check.
 */

CREATE FUNCTION app_public.tg_user_emails__verify_account_on_verified() RETURNS trigger AS
$$
BEGIN
    UPDATE app_public.users SET is_verified = TRUE WHERE id = new.user_id AND is_verified IS FALSE;
    RETURN new;
END;
$$ LANGUAGE plpgsql STRICT
                    VOLATILE
                    SECURITY DEFINER
                    SET search_path TO pg_catalog, public, pg_temp;

CREATE TRIGGER _500_verify_account_on_verified
    AFTER INSERT OR UPDATE OF is_verified
    ON app_public.user_emails
    FOR EACH ROW
    WHEN (new.is_verified IS TRUE)
EXECUTE PROCEDURE app_public.tg_user_emails__verify_account_on_verified();

--! split: 1040-user_authentications.sql
/*
 * In addition to logging in with username/email and password, users may use
 * other authentication methods, such as "social login" (OAuth) with GitHub,
 * Twitter, Facebook, etc. We store details of these logins to the
 * user_authentications and user_authentication_secrets tables.
 *
 * The user is allowed to delete entries in this table (which will unlink them
 * from that service), but adding records to the table requires elevated
 * privileges (it's managed by the `installPassportStrategy.ts` middleware,
 * which calls out to the `app_private.link_or_register_user` database
 * function).
 */
CREATE TABLE app_public.user_authentications
(
    id         uuid PRIMARY KEY     DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES app_public.users ON DELETE CASCADE,
    service    text        NOT NULL,
    identifier text        NOT NULL,
    details    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    CONSTRAINT uniq_user_authentications UNIQUE (service, identifier)
);

ALTER TABLE app_public.user_authentications
    ENABLE ROW LEVEL SECURITY;

-- Make it efficient to find all the authentications for a particular user.
CREATE INDEX ON app_public.user_authentications (user_id);

-- Keep created_at and updated_at up to date.
CREATE TRIGGER _100_timestamps
    BEFORE INSERT OR UPDATE
    ON app_public.user_authentications
    FOR EACH ROW
EXECUTE PROCEDURE app_private.tg__timestamps();

COMMENT ON TABLE app_public.user_authentications IS
    E'Contains information about the login providers this user has used, so that they may disconnect them should they wish.';
COMMENT ON COLUMN app_public.user_authentications.service IS
    E'The login service used, e.g. `twitter` or `github`.';
COMMENT ON COLUMN app_public.user_authentications.identifier IS
    E'A unique identifier for the user within the login service.';
COMMENT ON COLUMN app_public.user_authentications.details IS
    E'Additional profile details extracted from this login method';

-- Users may view and delete their social logins.
CREATE POLICY select_own ON app_public.user_authentications FOR SELECT USING (user_id = app_public.current_user_id());
CREATE POLICY delete_own ON app_public.user_authentications FOR DELETE USING (user_id = app_public.current_user_id());
-- TODO: on delete, check this isn't the last one, or that they have a verified
-- email address or password. For now we're not worrying about that since all
-- the OAuth providers we use verify the email address.

-- Notify the user if a social login is removed.
CREATE TRIGGER _500_audit_removed
    AFTER DELETE
    ON app_public.user_authentications
    FOR EACH ROW
EXECUTE PROCEDURE app_private.tg__add_audit_job(
        'unlinked_account',
        'user_id',
        'service',
        'identifier'
    );
-- NOTE: we don't need to notify when a linked account is added here because
-- that's handled in the link_or_register_user function.

GRANT SELECT ON app_public.user_authentications TO :DATABASE_VISITOR;
GRANT DELETE ON app_public.user_authentications TO :DATABASE_VISITOR;

/**********/

-- This table contains secret information for each user_authentication; could
-- be things like access tokens, refresh tokens, profile information. Whatever
-- the passport strategy deems necessary.
CREATE TABLE app_private.user_authentication_secrets
(
    user_authentication_id uuid  NOT NULL PRIMARY KEY REFERENCES app_public.user_authentications ON DELETE CASCADE,
    details                jsonb NOT NULL DEFAULT '{}'::jsonb
);
ALTER TABLE app_private.user_authentication_secrets
    ENABLE ROW LEVEL SECURITY;

-- NOTE: user_authentication_secrets doesn't need an auto-inserter as we handle
-- that everywhere that can create a user_authentication row.

--! split: 1100-login.sql
/*
 * This function handles logging in a user with their username (or email
 * address) and password.
 *
 * Note that it is not in app_public; this function is intended to be called
 * with elevated privileges (namely from `PassportLoginPlugin.ts`). The reason
 * for this is because we want to be able to track failed login attempts (to
 * help protect user accounts). If this were callable by a user, they could
 * roll back the transaction when a login fails and no failed attempts would be
 * logged, effectively giving them infinite retries. We want to disallow this,
 * so we only let code call into `login` that we trust to not roll back the
 * transaction afterwards.
 */
CREATE FUNCTION app_private.login(username citext, password text) RETURNS app_private.sessions AS
$$
DECLARE
    v_user                          app_public.users;
    v_user_secret                   app_private.user_secrets;
    v_login_attempt_window_duration interval = INTERVAL '5 minutes';
    v_session                       app_private.sessions;
BEGIN
    IF username LIKE '%@%' THEN
        -- It's an email
        SELECT users.*
        INTO v_user
        FROM app_public.users
                 INNER JOIN app_public.user_emails
                            ON (user_emails.user_id = users.id)
        WHERE user_emails.email = login.username
        ORDER BY user_emails.is_verified DESC, -- Prefer verified email
                 user_emails.created_at ASC    -- Failing that, prefer the first registered (unverified users _should_ verify before logging in)
        LIMIT 1;
    ELSE
        -- It's a username
        SELECT users.*
        INTO v_user
        FROM app_public.users
        WHERE users.username = login.username;
    END IF;

    IF NOT (v_user IS NULL) THEN
        -- Load their secrets
        SELECT *
        INTO v_user_secret
        FROM app_private.user_secrets
        WHERE user_secrets.user_id = v_user.id;

        -- Have there been too many login attempts?
        IF (
                v_user_secret.first_failed_password_attempt IS NOT NULL
                AND
                v_user_secret.first_failed_password_attempt > NOW() - v_login_attempt_window_duration
                AND
                v_user_secret.failed_password_attempts >= 3
            ) THEN
            RAISE EXCEPTION 'User account locked - too many login attempts. Try again after 5 minutes.' USING ERRCODE = 'LOCKD';
        END IF;

        -- Not too many login attempts, let's check the password.
        -- NOTE: `password_hash` could be null, this is fine since `NULL = NULL` is null, and null is falsy.
        IF v_user_secret.password_hash = crypt(password, v_user_secret.password_hash) THEN
            -- Excellent - they're logged in! Let's reset the attempt tracking
            UPDATE app_private.user_secrets
            SET failed_password_attempts      = 0,
                first_failed_password_attempt = NULL,
                last_login_at                 = NOW()
            WHERE user_id = v_user.id;
            -- Create a session for the user
            INSERT INTO app_private.sessions (user_id) VALUES (v_user.id) RETURNING * INTO v_session;
            -- And finally return the session
            RETURN v_session;
        ELSE
            -- Wrong password, bump all the attempt tracking figures
            UPDATE app_private.user_secrets
            SET failed_password_attempts      = (CASE
                                                     WHEN first_failed_password_attempt IS NULL OR
                                                          first_failed_password_attempt <
                                                          NOW() - v_login_attempt_window_duration THEN 1
                                                     ELSE failed_password_attempts + 1 END),
                first_failed_password_attempt = (CASE
                                                     WHEN first_failed_password_attempt IS NULL OR
                                                          first_failed_password_attempt <
                                                          NOW() - v_login_attempt_window_duration THEN NOW()
                                                     ELSE first_failed_password_attempt END)
            WHERE user_id = v_user.id;
            RETURN NULL; -- Must not throw otherwise transaction will be aborted and attempts won't be recorded
        END IF;
    ELSE
        -- No user with that email/username was found
        RETURN NULL;
    END IF;
END;
$$ LANGUAGE plpgsql STRICT
                    VOLATILE;

COMMENT ON FUNCTION app_private.login(username citext, password text) IS
    E'Returns a user that matches the username/password combo, or null on failure.';

--! split: 1110-logout.sql
/*
 * Logging out deletes the session, and clears the session_id in the
 * transaction. This is a `SECURITY DEFINER` function, so we check that the
 * user is allowed to do it by matching the current_session_id().
 */
CREATE FUNCTION app_public.logout() RETURNS void AS
$$
BEGIN
    -- Delete the session
    DELETE FROM app_private.sessions WHERE uuid = app_public.current_session_id();
    -- Clear the identifier from the transaction
    PERFORM SET_CONFIG('jwt.claims.session_id', '', TRUE);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
                    VOLATILE
                    SET search_path TO pg_catalog, public, pg_temp;

--! split: 1120-forgot_password.sql
/*
 * When a user forgets their password we want to let them set a new one; but we
 * need to be very careful with this. We don't want to reveal whether or not an
 * account exists by the email address, so we email the entered email address
 * whether or not it's registered. If it's not registered, we track these
 * attempts in `unregistered_email_password_resets` to ensure that we don't
 * allow spamming the address; otherwise we store it to `user_email_secrets`.
 *
 * `app_public.forgot_password` is responsible for checking these things and
 * queueing a reset password token to be emailed to the user. For what happens
 * after the user receives this email, see instead `app_private.reset_password`.
 *
 * NOTE: unlike app_private.login and app_private.reset_password, rolling back
 * the results of this function will not cause any security issues so we do not
 * need to call it indirectly as we do for those other functions. (Rolling back
 * will undo the tracking of when we sent the email but it will also prevent
 * the email being sent, so it's harmless.)
 */

CREATE TABLE app_private.unregistered_email_password_resets
(
    email          citext
        CONSTRAINT unregistered_email_pkey PRIMARY KEY,
    attempts       int         NOT NULL DEFAULT 1,
    latest_attempt timestamptz NOT NULL
);
COMMENT ON TABLE app_private.unregistered_email_password_resets IS
    E'If someone tries to recover the password for an email that is not registered in our system, this table enables us to rate-limit outgoing emails to avoid spamming.';
COMMENT ON COLUMN app_private.unregistered_email_password_resets.attempts IS
    E'We store the number of attempts to help us detect accounts being attacked.';
COMMENT ON COLUMN app_private.unregistered_email_password_resets.latest_attempt IS
    E'We store the time the last password reset was sent to this email to prevent the email getting flooded.';

/**********/

CREATE FUNCTION app_public.forgot_password(email citext) RETURNS void AS
$$
DECLARE
    v_user_email                        app_public.user_emails;
    v_token                             text;
    v_token_min_duration_between_emails interval    = INTERVAL '3 minutes';
    v_token_max_duration                interval    = INTERVAL '3 days';
    v_now                               timestamptz = CLOCK_TIMESTAMP(); -- Function can be called multiple during transaction
    v_latest_attempt                    timestamptz;
BEGIN
    -- Find the matching user_email:
    SELECT user_emails.*
    INTO v_user_email
    FROM app_public.user_emails
    WHERE user_emails.email = forgot_password.email
    ORDER BY is_verified DESC, id DESC;

    -- If there is no match:
    IF v_user_email IS NULL THEN
        -- This email doesn't exist in the system; trigger an email stating as much.

        -- We do not allow this email to be triggered more than once every 15
        -- minutes, so we need to track it:
        INSERT INTO app_private.unregistered_email_password_resets (email, latest_attempt)
        VALUES (forgot_password.email, v_now)
        ON CONFLICT ON CONSTRAINT unregistered_email_pkey
            DO UPDATE
            SET latest_attempt = v_now, attempts = unregistered_email_password_resets.attempts + 1
        WHERE unregistered_email_password_resets.latest_attempt < v_now - INTERVAL '15 minutes'
        RETURNING latest_attempt INTO v_latest_attempt;

        IF v_latest_attempt = v_now THEN
            PERFORM graphile_worker.add_job(
                    'user__forgot_password_unregistered_email',
                    JSON_BUILD_OBJECT('email', forgot_password.email::text)
                );
        END IF;

        -- TODO: we should clear out the unregistered_email_password_resets table periodically.

        RETURN;
    END IF;

    -- There was a match.
    -- See if we've triggered a reset recently:
    IF EXISTS(
            SELECT 1
            FROM app_private.user_email_secrets
            WHERE user_email_id = v_user_email.id
              AND password_reset_email_sent_at IS NOT NULL
              AND password_reset_email_sent_at > v_now - v_token_min_duration_between_emails
        ) THEN
        -- If so, take no action.
        RETURN;
    END IF;

    -- Fetch or generate reset token:
    UPDATE app_private.user_secrets
    SET reset_password_token           = (
        CASE
            WHEN reset_password_token IS NULL OR reset_password_token_generated < v_now - v_token_max_duration
                THEN ENCODE(gen_random_bytes(7), 'hex')
            ELSE reset_password_token
            END
        ),
        reset_password_token_generated = (
            CASE
                WHEN reset_password_token IS NULL OR reset_password_token_generated < v_now - v_token_max_duration
                    THEN v_now
                ELSE reset_password_token_generated
                END
            )
    WHERE user_id = v_user_email.user_id
    RETURNING reset_password_token INTO v_token;

    -- Don't allow spamming an email:
    UPDATE app_private.user_email_secrets
    SET password_reset_email_sent_at = v_now
    WHERE user_email_id = v_user_email.id;

    -- Trigger email send:
    PERFORM graphile_worker.add_job(
            'user__forgot_password',
            JSON_BUILD_OBJECT('id', v_user_email.user_id, 'email', v_user_email.email::text, 'token', v_token)
        );

END;
$$ LANGUAGE plpgsql STRICT
                    SECURITY DEFINER
                    VOLATILE
                    SET search_path TO pg_catalog, public, pg_temp;

COMMENT ON FUNCTION app_public.forgot_password(email public.citext) IS
    E'If you''ve forgotten your password, give us one of your email addresses and we''ll send you a reset token. Note this only works if you have added an email address!';

--! split: 1130-reset_password.sql
/*
 * This is the second half of resetting a users password, please see
 * `app_public.forgot_password` for the first half.
 *
 * The `app_private.reset_password` function checks the reset token is correct
 * and sets the user's password to be the newly provided password, assuming
 * `assert_valid_password` is happy with it. If the attempt fails, this is
 * logged to avoid a brute force attack. Since we cannot risk this tracking
 * being lost (e.g. by a later error rolling back the transaction), we put this
 * function into app_private and explicitly call it from the `resetPassword`
 * field in `PassportLoginPlugin.ts`.
 */

CREATE FUNCTION app_private.assert_valid_password(new_password text) RETURNS void AS
$$
BEGIN
    -- TODO: add better assertions!
    IF LENGTH(new_password) < 8 THEN
        RAISE EXCEPTION 'Password is too weak' USING ERRCODE = 'WEAKP';
    END IF;
END;
$$ LANGUAGE plpgsql VOLATILE;

CREATE FUNCTION app_private.reset_password(user_id uuid, reset_token text, new_password text) RETURNS boolean AS
$$
DECLARE
    v_user               app_public.users;
    v_user_secret        app_private.user_secrets;
    v_token_max_duration interval = INTERVAL '3 days';
BEGIN
    SELECT users.*
    INTO v_user
    FROM app_public.users
    WHERE id = user_id;

    IF NOT (v_user IS NULL) THEN
        -- Load their secrets
        SELECT *
        INTO v_user_secret
        FROM app_private.user_secrets
        WHERE user_secrets.user_id = v_user.id;

        -- Have there been too many reset attempts?
        IF (
                v_user_secret.first_failed_reset_password_attempt IS NOT NULL
                AND
                v_user_secret.first_failed_reset_password_attempt > NOW() - v_token_max_duration
                AND
                v_user_secret.failed_reset_password_attempts >= 20
            ) THEN
            RAISE EXCEPTION 'Password reset locked - too many reset attempts' USING ERRCODE = 'LOCKD';
        END IF;

        -- Not too many reset attempts, let's check the token
        IF v_user_secret.reset_password_token = reset_token THEN
            -- Excellent - they're legit

            PERFORM app_private.assert_valid_password(new_password);

            -- Let's reset the password as requested
            UPDATE app_private.user_secrets
            SET password_hash                       = crypt(new_password, gen_salt('bf')),
                failed_password_attempts            = 0,
                first_failed_password_attempt       = NULL,
                reset_password_token                = NULL,
                reset_password_token_generated      = NULL,
                failed_reset_password_attempts      = 0,
                first_failed_reset_password_attempt = NULL
            WHERE user_secrets.user_id = v_user.id;

            -- Revoke the users' sessions
            DELETE
            FROM app_private.sessions
            WHERE sessions.user_id = v_user.id;

            -- Notify user their password was reset
            PERFORM graphile_worker.add_job(
                    'user__audit',
                    JSON_BUILD_OBJECT(
                            'type', 'reset_password',
                            'user_id', v_user.id,
                            'current_user_id', app_public.current_user_id()
                        ));

            RETURN TRUE;
        ELSE
            -- Wrong token, bump all the attempt tracking figures
            UPDATE app_private.user_secrets
            SET failed_reset_password_attempts      = (CASE
                                                           WHEN first_failed_reset_password_attempt IS NULL OR
                                                                first_failed_reset_password_attempt <
                                                                NOW() - v_token_max_duration THEN 1
                                                           ELSE failed_reset_password_attempts + 1 END),
                first_failed_reset_password_attempt = (CASE
                                                           WHEN first_failed_reset_password_attempt IS NULL OR
                                                                first_failed_reset_password_attempt <
                                                                NOW() - v_token_max_duration THEN NOW()
                                                           ELSE first_failed_reset_password_attempt END)
            WHERE user_secrets.user_id = v_user.id;
            RETURN NULL;
        END IF;
    ELSE
        -- No user with that id was found
        RETURN NULL;
    END IF;
END;
$$ LANGUAGE plpgsql STRICT
                    VOLATILE;

--! split: 1140-request_account_deletion.sql
/*
 * For security reasons we don't want to allow a user to just delete their user
 * account without confirmation; so we have them request deletion, receive an
 * email, and then click the link in the email and press a button to confirm
 * deletion. This function handles the first step in this process; see
 * `app_public.confirm_account_deletion` for the second half.
 */

CREATE FUNCTION app_public.request_account_deletion() RETURNS boolean AS
$$
DECLARE
    v_user_email         app_public.user_emails;
    v_token              text;
    v_token_max_duration interval = INTERVAL '3 days';
BEGIN
    IF app_public.current_user_id() IS NULL THEN
        RAISE EXCEPTION 'You must log in to delete your account' USING ERRCODE = 'LOGIN';
    END IF;

    -- Get the email to send account deletion token to
    SELECT *
    INTO v_user_email
    FROM app_public.user_emails
    WHERE user_id = app_public.current_user_id()
    ORDER BY is_primary DESC, is_verified DESC, id DESC
    LIMIT 1;

    -- Fetch or generate token
    UPDATE app_private.user_secrets
    SET delete_account_token           = (
        CASE
            WHEN delete_account_token IS NULL OR delete_account_token_generated < NOW() - v_token_max_duration
                THEN ENCODE(gen_random_bytes(7), 'hex')
            ELSE delete_account_token
            END
        ),
        delete_account_token_generated = (
            CASE
                WHEN delete_account_token IS NULL OR delete_account_token_generated < NOW() - v_token_max_duration
                    THEN NOW()
                ELSE delete_account_token_generated
                END
            )
    WHERE user_id = app_public.current_user_id()
    RETURNING delete_account_token INTO v_token;

    -- Trigger email send
    PERFORM graphile_worker.add_job('user__send_delete_account_email',
                                    JSON_BUILD_OBJECT('email', v_user_email.email::text, 'token', v_token));
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql STRICT
                    SECURITY DEFINER
                    VOLATILE
                    SET search_path TO pg_catalog, public, pg_temp;

COMMENT ON FUNCTION app_public.request_account_deletion() IS
    E'Begin the account deletion flow by requesting the confirmation email';

--! split: 1150-confirm_account_deletion.sql
/*
 * This is the second half of the account deletion process, for the first half
 * see `app_public.request_account_deletion`.
 */
CREATE FUNCTION app_public.confirm_account_deletion(token text) RETURNS boolean AS
$$
DECLARE
    v_user_secret        app_private.user_secrets;
    v_token_max_duration interval = INTERVAL '3 days';
BEGIN
    IF app_public.current_user_id() IS NULL THEN
        RAISE EXCEPTION 'You must log in to delete your account' USING ERRCODE = 'LOGIN';
    END IF;

    SELECT *
    INTO v_user_secret
    FROM app_private.user_secrets
    WHERE user_secrets.user_id = app_public.current_user_id();

    IF v_user_secret IS NULL THEN
        -- Success: they're already deleted
        RETURN TRUE;
    END IF;

    -- Check the token
    IF (
        -- token is still valid
                v_user_secret.delete_account_token_generated > NOW() - v_token_max_duration
            AND
            -- token matches
                v_user_secret.delete_account_token = token
        ) THEN
        -- Token passes; delete their account :(
        DELETE FROM app_public.users WHERE id = app_public.current_user_id();
        RETURN TRUE;
    END IF;

    RAISE EXCEPTION 'The supplied token was incorrect - perhaps you''re logged in to the wrong account, or the token has expired?' USING ERRCODE = 'DNIED';
END;
$$ LANGUAGE plpgsql STRICT
                    VOLATILE
                    SECURITY DEFINER
                    SET search_path TO pg_catalog, public, pg_temp;

COMMENT ON FUNCTION app_public.confirm_account_deletion(token text) IS
    E'If you''re certain you want to delete your account, use `requestAccountDeletion` to request an account deletion token, and then supply the token through this mutation to complete account deletion.';

--! split: 1160-change_password.sql
/*
 * To change your password you must specify your previous password. The form in
 * the web UI may confirm that the new password was typed correctly by making
 * the user type it twice, but that isn't necessary in the API.
 */

CREATE FUNCTION app_public.change_password(old_password text, new_password text) RETURNS boolean AS
$$
DECLARE
    v_user        app_public.users;
    v_user_secret app_private.user_secrets;
BEGIN
    SELECT users.*
    INTO v_user
    FROM app_public.users
    WHERE id = app_public.current_user_id();

    IF NOT (v_user IS NULL) THEN
        -- Load their secrets
        SELECT *
        INTO v_user_secret
        FROM app_private.user_secrets
        WHERE user_secrets.user_id = v_user.id;

        IF v_user_secret.password_hash = crypt(old_password, v_user_secret.password_hash) THEN
            PERFORM app_private.assert_valid_password(new_password);

            -- Reset the password as requested
            UPDATE app_private.user_secrets
            SET password_hash = crypt(new_password, gen_salt('bf'))
            WHERE user_secrets.user_id = v_user.id;

            -- Revoke all other sessions
            DELETE
            FROM app_private.sessions
            WHERE sessions.user_id = v_user.id
              AND sessions.uuid <> app_public.current_session_id();

            -- Notify user their password was changed
            PERFORM graphile_worker.add_job(
                    'user__audit',
                    JSON_BUILD_OBJECT(
                            'type', 'change_password',
                            'user_id', v_user.id,
                            'current_user_id', app_public.current_user_id()
                        ));

            RETURN TRUE;
        ELSE
            RAISE EXCEPTION 'Incorrect password' USING ERRCODE = 'CREDS';
        END IF;
    ELSE
        RAISE EXCEPTION 'You must log in to change your password' USING ERRCODE = 'LOGIN';
    END IF;
END;
$$ LANGUAGE plpgsql STRICT
                    VOLATILE
                    SECURITY DEFINER
                    SET search_path TO pg_catalog, public, pg_temp;

COMMENT ON FUNCTION app_public.change_password(old_password text, new_password text) IS
    E'Enter your old password and a new password to change your password.';

GRANT EXECUTE ON FUNCTION app_public.change_password(text, text) TO :DATABASE_VISITOR;

--! split: 1200-user-registration.sql
/*
 * A user account may be created explicitly via the GraphQL `register` mutation
 * (which calls `really_create_user` below), or via OAuth (which, via
 * `installPassportStrategy.ts`, calls link_or_register_user below, which may
 * then call really_create_user). Ultimately `really_create_user` is called in
 * all cases to create a user account within our system, so it must do
 * everything we'd expect in this case including validating username/password,
 * setting the password (if any), storing the email address, etc.
 */

CREATE FUNCTION app_private.really_create_user(
    username citext,
    email text,
    email_is_verified bool,
    name text,
    avatar_url text,
    password text DEFAULT NULL
) RETURNS app_public.users AS
$$
DECLARE
    v_user     app_public.users;
    v_username citext = username;
BEGIN
    IF password IS NOT NULL THEN
        PERFORM app_private.assert_valid_password(password);
    END IF;
    IF email IS NULL THEN
        RAISE EXCEPTION 'Email is required' USING ERRCODE = 'MODAT';
    END IF;

    -- Insert the new user
    INSERT INTO app_public.users (username, name, avatar_url)
    VALUES (v_username, name, avatar_url)
    RETURNING * INTO v_user;

    -- Add the user's email
    INSERT INTO app_public.user_emails (user_id, email, is_verified, is_primary)
    VALUES (v_user.id, email, email_is_verified, email_is_verified);

    -- Store the password
    IF password IS NOT NULL THEN
        UPDATE app_private.user_secrets
        SET password_hash = crypt(password, gen_salt('bf'))
        WHERE user_id = v_user.id;
    END IF;

    -- Refresh the user
    SELECT * INTO v_user FROM app_public.users WHERE id = v_user.id;

    RETURN v_user;
END;
$$ LANGUAGE plpgsql VOLATILE
                    SET search_path TO pg_catalog, public, pg_temp;

COMMENT ON FUNCTION app_private.really_create_user(username citext, email text, email_is_verified bool, name text, avatar_url text, password text) IS
    E'Creates a user account. All arguments are optional, it trusts the calling method to perform sanitisation.';

/**********/

/*
 * The `register_user` function is called by `link_or_register_user` when there
 * is no matching user to link the login to, so we want to register the user
 * using OAuth or similar credentials.
 */

CREATE FUNCTION app_private.register_user(
    f_service character varying,
    f_identifier character varying,
    f_profile json,
    f_auth_details json,
    f_email_is_verified boolean DEFAULT FALSE
) RETURNS app_public.users AS
$$
DECLARE
    v_user                   app_public.users;
    v_email                  citext;
    v_name                   text;
    v_username               citext;
    v_avatar_url             text;
    v_user_authentication_id uuid;
BEGIN
    -- Extract data from the user’s OAuth profile data.
    v_email := f_profile ->> 'email';
    v_name := f_profile ->> 'name';
    v_username := f_profile ->> 'username';
    v_avatar_url := f_profile ->> 'avatar_url';

    -- Sanitise the username, and make it unique if necessary.
    IF v_username IS NULL THEN
        v_username = COALESCE(v_name, 'user');
    END IF;
    v_username = REGEXP_REPLACE(v_username, '^[^a-z]+', '', 'gi');
    v_username = REGEXP_REPLACE(v_username, '[^a-z0-9]+', '_', 'gi');
    IF v_username IS NULL OR LENGTH(v_username) < 3 THEN
        v_username = 'user';
    END IF;
    SELECT (
               CASE
                   WHEN i = 0 THEN v_username
                   ELSE v_username || i::text
                   END
               )
    INTO v_username
    FROM GENERATE_SERIES(0, 1000) i
    WHERE NOT EXISTS(
            SELECT 1
            FROM app_public.users
            WHERE users.username = (
                CASE
                    WHEN i = 0 THEN v_username
                    ELSE v_username || i::text
                    END
                )
        )
    LIMIT 1;

    -- Create the user account
    v_user = app_private.really_create_user(
            username => v_username,
            email => v_email,
            email_is_verified => f_email_is_verified,
            name => v_name,
            avatar_url => v_avatar_url
        );

    -- Insert the user’s private account data (e.g. OAuth tokens)
    INSERT INTO app_public.user_authentications (user_id, service, identifier, details)
    VALUES (v_user.id, f_service, f_identifier, f_profile)
    RETURNING id INTO v_user_authentication_id;
    INSERT INTO app_private.user_authentication_secrets (user_authentication_id, details)
    VALUES (v_user_authentication_id, f_auth_details);

    RETURN v_user;
END;
$$ LANGUAGE plpgsql VOLATILE
                    SECURITY DEFINER
                    SET search_path TO pg_catalog, public, pg_temp;

COMMENT ON FUNCTION app_private.register_user(f_service character varying, f_identifier character varying, f_profile json, f_auth_details json, f_email_is_verified boolean) IS
    E'Used to register a user from information gleaned from OAuth. Primarily used by link_or_register_user';

/**********/

/*
 * The `link_or_register_user` function is called from
 * `installPassportStrategy.ts` when a user logs in with a social login
 * provider (OAuth), e.g. GitHub, Facebook, etc. If the user is already logged
 * in then the new provider will be linked to the users account, otherwise we
 * will try to retrieve an existing account using these details (matching the
 * service/identifier or the email address), and failing that we will register
 * a new user account linked to this service via the `register_user` function.
 *
 * This function is also responsible for keeping details in sync with the login
 * provider whenever the user logs in; you'll see this in the `update`
 * statemets towards the bottom of the function.
 */

CREATE FUNCTION app_private.link_or_register_user(
    f_user_id uuid,
    f_service character varying,
    f_identifier character varying,
    f_profile json,
    f_auth_details json
) RETURNS app_public.users AS
$$
DECLARE
    v_matched_user_id           uuid;
    v_matched_authentication_id uuid;
    v_email                     citext;
    v_name                      text;
    v_avatar_url                text;
    v_user                      app_public.users;
    v_user_email                app_public.user_emails;
BEGIN
    -- See if a user account already matches these details
    SELECT id, user_id
    INTO v_matched_authentication_id, v_matched_user_id
    FROM app_public.user_authentications
    WHERE service = f_service
      AND identifier = f_identifier
    LIMIT 1;

    IF v_matched_user_id IS NOT NULL AND f_user_id IS NOT NULL AND v_matched_user_id <> f_user_id THEN
        RAISE EXCEPTION 'A different user already has this account linked.' USING ERRCODE = 'TAKEN';
    END IF;

    v_email = f_profile ->> 'email';
    v_name := f_profile ->> 'name';
    v_avatar_url := f_profile ->> 'avatar_url';

    IF v_matched_authentication_id IS NULL THEN
        IF f_user_id IS NOT NULL THEN
            -- Link new account to logged in user account
            INSERT INTO app_public.user_authentications (user_id, service, identifier, details)
            VALUES (f_user_id, f_service, f_identifier, f_profile)
            RETURNING id, user_id INTO v_matched_authentication_id, v_matched_user_id;
            INSERT INTO app_private.user_authentication_secrets (user_authentication_id, details)
            VALUES (v_matched_authentication_id, f_auth_details);
            PERFORM graphile_worker.add_job(
                    'user__audit',
                    JSON_BUILD_OBJECT(
                            'type', 'linked_account',
                            'user_id', f_user_id,
                            'extra1', f_service,
                            'extra2', f_identifier,
                            'current_user_id', app_public.current_user_id()
                        ));
        ELSIF v_email IS NOT NULL THEN
            -- See if the email is registered
            SELECT * INTO v_user_email FROM app_public.user_emails WHERE email = v_email AND is_verified IS TRUE;
            IF v_user_email IS NOT NULL THEN
                -- User exists!
                INSERT INTO app_public.user_authentications (user_id, service, identifier, details)
                VALUES (v_user_email.user_id, f_service, f_identifier, f_profile)
                RETURNING id, user_id INTO v_matched_authentication_id, v_matched_user_id;
                INSERT INTO app_private.user_authentication_secrets (user_authentication_id, details)
                VALUES (v_matched_authentication_id, f_auth_details);
                PERFORM graphile_worker.add_job(
                        'user__audit',
                        JSON_BUILD_OBJECT(
                                'type', 'linked_account',
                                'user_id', f_user_id,
                                'extra1', f_service,
                                'extra2', f_identifier,
                                'current_user_id', app_public.current_user_id()
                            ));
            END IF;
        END IF;
    END IF;
    IF v_matched_user_id IS NULL AND f_user_id IS NULL AND v_matched_authentication_id IS NULL THEN
        -- Create and return a new user account
        RETURN app_private.register_user(f_service, f_identifier, f_profile, f_auth_details, TRUE);
    ELSE
        IF v_matched_authentication_id IS NOT NULL THEN
            UPDATE app_public.user_authentications
            SET details = f_profile
            WHERE id = v_matched_authentication_id;
            UPDATE app_private.user_authentication_secrets
            SET details = f_auth_details
            WHERE user_authentication_id = v_matched_authentication_id;
            UPDATE app_public.users
            SET name       = COALESCE(users.name, v_name),
                avatar_url = COALESCE(users.avatar_url, v_avatar_url)
            WHERE id = v_matched_user_id
            RETURNING * INTO v_user;
            RETURN v_user;
        ELSE
            -- v_matched_authentication_id is null
            -- -> v_matched_user_id is null (they're paired)
            -- -> f_user_id is not null (because the if clause above)
            -- -> v_matched_authentication_id is not null (because of the separate if block above creating a user_authentications)
            -- -> contradiction.
            RAISE EXCEPTION 'This should not occur';
        END IF;
    END IF;
END;
$$ LANGUAGE plpgsql VOLATILE
                    SECURITY DEFINER
                    SET search_path TO pg_catalog, public, pg_temp;

COMMENT ON FUNCTION app_private.link_or_register_user(f_user_id uuid, f_service character varying, f_identifier character varying, f_profile json, f_auth_details json) IS
    E'If you''re logged in, this will link an additional OAuth login to your account if necessary. If you''re logged out it may find if an account already exists (based on OAuth details or email address) and return that, or create a new user account if necessary.';

--! split: 1210-make_email_primary.sql
/*
 * The user is only allowed to have one primary email, and that email must be
 * verified. This function lets the user change which of their verified emails
 * is the primary email.
 */

CREATE FUNCTION app_public.make_email_primary(email_id uuid) RETURNS app_public.user_emails AS
$$
DECLARE
    v_user_email app_public.user_emails;
BEGIN
    SELECT *
    INTO v_user_email
    FROM app_public.user_emails
    WHERE id = email_id AND user_id = app_public.current_user_id();
    IF v_user_email IS NULL THEN
        RAISE EXCEPTION 'That''s not your email' USING ERRCODE = 'DNIED';
        RETURN NULL;
    END IF;
    IF v_user_email.is_verified IS FALSE THEN
        RAISE EXCEPTION 'You may not make an unverified email primary' USING ERRCODE = 'VRFY1';
    END IF;
    UPDATE app_public.user_emails
    SET is_primary = FALSE
    WHERE user_id = app_public.current_user_id()
      AND is_primary IS TRUE
      AND id <> email_id;
    UPDATE app_public.user_emails
    SET is_primary = TRUE
    WHERE user_id = app_public.current_user_id()
      AND is_primary IS NOT TRUE
      AND id = email_id
    RETURNING * INTO v_user_email;
    RETURN v_user_email;
END;
$$ LANGUAGE plpgsql STRICT
                    VOLATILE
                    SECURITY DEFINER
                    SET search_path TO pg_catalog, public, pg_temp;
COMMENT ON FUNCTION app_public.make_email_primary(email_id uuid) IS
    E'Your primary email is where we''ll notify of account events; other emails may be used for discovery or login. Use this when you''re changing your email address.';

--! split: 1220-resend_email_verification_code.sql
/*
 * If you don't receive the email verification email, you can trigger a resend
 * with this function.
 */
CREATE FUNCTION app_public.resend_email_verification_code(email_id uuid) RETURNS boolean AS
$$
BEGIN
    IF EXISTS(
            SELECT 1
            FROM app_public.user_emails
            WHERE user_emails.id = email_id
              AND user_id = app_public.current_user_id()
              AND is_verified IS FALSE
        ) THEN
        PERFORM graphile_worker.add_job('user_emails__send_verification', JSON_BUILD_OBJECT('id', email_id));
        RETURN TRUE;
    END IF;
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STRICT
                    VOLATILE
                    SECURITY DEFINER
                    SET search_path TO pg_catalog, public, pg_temp;
COMMENT ON FUNCTION app_public.resend_email_verification_code(email_id uuid) IS
    E'If you didn''t receive the verification code for this email, we can resend it. We silently cap the rate of resends on the backend, so calls to this function may not result in another email being sent if it has been called recently.';
