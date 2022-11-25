/**
 * The Postgres pool is initialized in server.js outside of remix's context
 */
import { Pool } from "pg";

// @ts-ignore
const pgPool: Pool = process.pgPool;

export default pgPool;
