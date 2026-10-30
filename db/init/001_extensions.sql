-- db/init/001_extensions.sql
-- 컨테이너 최초 생성 시 1회 실행
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;