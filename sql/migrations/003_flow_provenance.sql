-- Additive: existing prototype flow/schema/experiment identities remain unchanged.
CREATE TABLE flow_provenance (
    flow_id bigint PRIMARY KEY REFERENCES flow,
    raw_fields jsonb NOT NULL
);
