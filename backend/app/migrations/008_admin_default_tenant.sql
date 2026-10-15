-- The tenant an admin sees right after signing in, chosen in the tenant menu ("Make demoB my
-- default"). NULL = their own tenant (users.tenant). Only admins can set it: they may view every
-- tenant anyway, while a viewer's tenant is a security boundary and never changes.
ALTER TABLE users ADD COLUMN default_tenant text;
