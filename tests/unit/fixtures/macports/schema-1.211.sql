-- MacPorts registry schema 1.211 as a base 2.8.1 registry holds it (requested_variants and
-- cxx_stdlib present, no snapshot tables).
CREATE TABLE metadata (key UNIQUE, value);
INSERT INTO metadata (key, value) VALUES ('version', '1.211');
INSERT INTO metadata (key, value) VALUES ('created', '1637138299');
CREATE TABLE ports (id INTEGER PRIMARY KEY, name TEXT COLLATE NOCASE, portfile TEXT, location TEXT, epoch INTEGER, version TEXT COLLATE VERSION, revision INTEGER, variants TEXT, requested_variants TEXT, state TEXT, date DATETIME, installtype TEXT, archs TEXT, requested INTEGER, os_platform TEXT, os_major INTEGER, cxx_stdlib TEXT, cxx_stdlib_overridden INTEGER, UNIQUE (name, epoch, version, revision, variants));
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
