-- Drop the verification table if it exists (optional for development/testing)
DROP TABLE IF EXISTS public.verification;

-- Create the verification table
CREATE TABLE public.verification (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(100) NOT NULL,
    verification_code VARCHAR(255) NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for email and verification_code
CREATE INDEX idx_email_verification ON public.verification(email);
CREATE INDEX idx_verification_code ON public.verification(verification_code);
