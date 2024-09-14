DROP TABLE IF EXISTS public.verification;

CREATE TABLE verification (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(100) NOT NULL,
    verification_code VARCHAR(255) NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_email_verification ON verification(email);
CREATE INDEX idx_verification_code ON verification(verification_code);
