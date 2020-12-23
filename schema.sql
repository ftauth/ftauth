CREATE TABLE tokens
(
    id uuid NOT NULL,
    type text NOT NULL,
    token text NOT NULL,
    exp date NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE clients (
    id uuid NOT NULL,
    type text NOT NULL,
    secret text,
    redirect_uris text[] NOT NULL,
    scopes text[] NOT NULL,
    PRIMARY KEY (id)
);
COMMENT ON COLUMN clients.redirect_uris IS 'At least one Redirect URI is required';
COMMENT ON COLUMN clients.scopes IS 'The list of scope IDs. At least one scope is required.';

-- Setup scopes table
CREATE TABLE scopes (
    name text NOT NULL,
    ruleset json NOT NULL,
    PRIMARY KEY (name)
);

CREATE TABLE sessions (

);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email text NOT NULL UNIQUE,
    password_hash text NOT NULL
    foreign_id text UNIQUE
);
COMMENT ON COLUMN users.foreign_id IS 'References the user''s ID on an external server (like the resource server), if different. Can be NULL if not needed.';

CREATE TABLE codes
(
    id uuid NOT NULL,
    code text NOT NULL,
    code_challenge text NOT NULL,
    code_challenge_method text NOT NULL DEFAULT 'S256',
    exp date NOT NULL,
    PRIMARY KEY (id)
);