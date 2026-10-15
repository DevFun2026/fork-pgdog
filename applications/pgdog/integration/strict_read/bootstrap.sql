CREATE ROLE strict_app LOGIN PASSWORD '__APP_PASSWORD__';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE TABLE public.strict_items (
    id BIGSERIAL PRIMARY KEY,
    value TEXT NOT NULL
);
GRANT CONNECT ON DATABASE app TO strict_app;
GRANT USAGE ON SCHEMA public TO strict_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.strict_items TO strict_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE public.strict_items_id_seq TO strict_app;

CREATE TYPE public.strict_enum AS ENUM ('alpha', 'beta');
CREATE TABLE public.strict_extended (
    id INTEGER PRIMARY KEY,
    payload JSONB,
    texts TEXT[],
    numbers NUMERIC[],
    dates DATE[],
    integers INTEGER[],
    kind public.strict_enum,
    CHECK (id >= 0)
);
CREATE INDEX strict_extended_payload ON public.strict_extended USING gin (payload);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.strict_extended TO strict_app;
