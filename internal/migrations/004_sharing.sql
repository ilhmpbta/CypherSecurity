CREATE TABLE share_requests (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id      UUID NOT NULL REFERENCES stored_files(id) ON DELETE CASCADE,
    owner_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    note         TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at   TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    imported_at  TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    CONSTRAINT check_share_not_self CHECK (owner_id <> requester_id)
);

CREATE UNIQUE INDEX idx_share_requests_pending ON share_requests(file_id, requester_id) WHERE status = 'pending';
CREATE INDEX idx_share_requests_owner ON share_requests(owner_id);
CREATE INDEX idx_share_requests_requester ON share_requests(requester_id);
CREATE INDEX idx_share_requests_file ON share_requests(file_id);

CREATE TABLE share_keys (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    share_request_id UUID NOT NULL UNIQUE REFERENCES share_requests(id) ON DELETE CASCADE,
    file_id          UUID NOT NULL REFERENCES stored_files(id) ON DELETE CASCADE,
    wrapped_dek      BYTEA NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_share_keys_request ON share_keys(share_request_id);
CREATE INDEX idx_share_keys_file ON share_keys(file_id);

CREATE OR REPLACE FUNCTION check_share_request_transition()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    IF OLD.status = 'pending' AND NEW.status IN ('approved', 'rejected') THEN
        RETURN NEW;
    END IF;

    IF OLD.status = 'approved' AND NEW.status = 'revoked' THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid state transition from % to %', OLD.status, NEW.status;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_share_request_transition
BEFORE UPDATE OF status ON share_requests
FOR EACH ROW
EXECUTE FUNCTION check_share_request_transition();
