-- Только локальная разработка. Не использовать этот пароль вне dev.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'health_app') THEN
        CREATE ROLE health_app
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOBYPASSRLS
            PASSWORD 'health_app_dev_only';
    ELSE
        ALTER ROLE health_app
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOBYPASSRLS
            PASSWORD 'health_app_dev_only';
    END IF;
END
$$;
