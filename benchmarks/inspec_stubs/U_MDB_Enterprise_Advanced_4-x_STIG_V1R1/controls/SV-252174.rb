control 'SV-252174' do
  title 'MongoDB must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceed the rights of a regular user.

DBMS functionality and the nature and requirements of databases will vary; so while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. The requirements for production servers will be more restrictive than those used for development and research.

MongoDB must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization).

In the case of a database management system, this requirement covers stored procedures, functions, triggers, views, etc.'
  desc 'check', 'If MongoDB supports only software development, experimentation and/or developer-level testing (that is, excluding production systems, integration testing, stress testing, and user acceptance testing), this is not a finding.

MongoDB only supports views and Change Streams (similar to triggers). Stored procedures and functions that are commonly found in relational databases are not supported by MongoDB.

Connect to MongoDB and authenticate as a user that has Database Administrator privileges.

Check each user of the database to verify that only authorized administrative users are granted the following privileges: createCollection and changeStream

Run the following command to get a list of all the databases in the system:
 show dbs

For each database in the system, identify any non-administrative users roles for the database:

 use database
 db.getUsers()

The server will return a document with the all users in the data and their associated roles.

Organizational or site-specific documentation should identify which administrative and non-administrative users exist.

For each role that a non-administrative user has in the database find the privileges each role has:

 db.getRole(rolename, { showPrivileges: true })

If any non-administrative user has a role that where the resource has the action of createCollections or changeStream this is a finding.'
  desc 'fix', 'Document and obtain approval for any non-administrative users to have roles that contain createCollections or changeSteam actions on resources.

For any non-administrative user that does not have approval, revoke these specific privileges  from that non-administrative users role.

Run the following commands in each database and for each non-administrative user that does not have approval to use the createCollections or changeStream actions on MongoDB resources:

 use database
 db.revokePrivilegesFromRole(
    rolename,
    [
        { resource: { resource }, actions: [ action, ... ] },
        ...
    ],
    { writeConcern }
)

In the above command the action will be either createCollections or changeStream.

There may be several resources in a role that contain these privileges and the removal process will require running the following command for each one.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55630r816987_chk'
  tag severity: 'medium'
  tag gid: 'V-252174'
  tag rid: 'SV-252174r816988_rule'
  tag stig_id: 'MD4X-00-005300'
  tag gtitle: 'SRG-APP-000378-DB-000365'
  tag fix_id: 'F-55580r813903_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
