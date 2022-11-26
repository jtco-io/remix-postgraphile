INSERT INTO app_public.users (id, username, name, is_verified, is_admin)
VALUES ('23e675b1-d581-4d85-16a3-7f73dbee72ad', 'admin', 'Admin User', TRUE, TRUE),
       ('da221b05-a99c-485d-a278-015e7baaeda2', 'jdoe', 'Jane Doe',
        TRUE, FALSE)
ON CONFLICT DO NOTHING;
