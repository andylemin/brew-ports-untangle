-- MacPorts registry schema 1.203 (the 1.202 tables of src/cregistry/sql.c plus the 1.203
-- index): negated_variants instead of requested_variants, no cxx_stdlib columns, rollback
-- journal mode (WAL arrived with 1.205).
CREATE TABLE metadata (key UNIQUE, value);
INSERT INTO metadata (key, value) VALUES ('version', '1.203');
INSERT INTO metadata (key, value) VALUES ('created', '1400000000');
CREATE TABLE ports (id INTEGER PRIMARY KEY, name TEXT COLLATE NOCASE, portfile CLOB, location TEXT, epoch INTEGER, version TEXT COLLATE VERSION, revision INTEGER, variants TEXT, negated_variants TEXT, state TEXT, date DATETIME, installtype TEXT, archs TEXT, requested INT, os_platform TEXT, os_major INTEGER, UNIQUE(name, epoch, version, revision, variants));
CREATE INDEX port_name ON ports(name, epoch, version, revision, variants);
CREATE INDEX port_state ON ports(state);
CREATE TABLE files (id INTEGER, path TEXT, actual_path TEXT, active INTEGER, binary BOOL, FOREIGN KEY(id) REFERENCES ports(id));
CREATE INDEX file_port ON files(id);
CREATE INDEX file_path ON files(path);
CREATE INDEX file_actual ON files(actual_path);
CREATE INDEX file_actual_nocase ON files(actual_path COLLATE NOCASE);
CREATE TABLE dependencies (id INTEGER, name TEXT, variants TEXT, FOREIGN KEY(id) REFERENCES ports(id));
CREATE INDEX dep_id ON dependencies(id);
CREATE INDEX dep_name ON dependencies(name);
CREATE TABLE portgroups (id INTEGER, name TEXT, version TEXT COLLATE VERSION, size INTEGER, sha256 TEXT, FOREIGN KEY(id) REFERENCES ports(id));
CREATE INDEX portgroup_id ON portgroups(id);
CREATE INDEX portgroup_open ON portgroups(id, name, version, size, sha256);
