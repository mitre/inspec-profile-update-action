control 'SV-252182' do
  title 'When updates are applied to MongoDB software, any software components that have been replaced or made unnecessary must be removed.'
  desc "Previous versions of DBMS components that are not removed from the information system after updates have been installed may be exploited by adversaries.

Some DBMSs' installation tools may remove older versions of software automatically from the information system. In other cases, manual review and removal will be required. In planning installations and upgrades, organizations must include steps (automated, manual, or both) to identify and remove the outdated modules.

A transition period may be necessary when both the old and the new software are required. This should be taken into account in the planning."
  desc 'check', 'Run the following command and observe the output. This command will determine if MongoDB has been installed with a package Manager (RedHat) and display what version is currently installed:

 rpm -q mongodb-enterprise-server.x86_64
mongodb-enterprise-server-4.4.8-1.el7.x86_64

The output of the command above indicates that MongoDB Enterprise Server has been installed with a package manager.

The preceding output is an example showing that MongoDB Enterprise Server Version 4.4.8 is installed. The specific version will be dependent on the actual version installed. Upgrading MongoDB with the same package manager used for installation will overwrite or remove files as part of the upgrade process.

If MongoDB was installed with a Package Manager (YUM/RPM for RedHat), this is not a finding.

Run the following command and observe the output.

 rpm -q mongodb-enterprise-server.x86_64
package mongodb-enterprise-server.x86_64 is not installed

The output of the command above indicates that MongoDB has not been installed via a package manager or may not have been installed at all.

If MongoDB has not been installed with a Package Manager (YUM/RPM for RedHat), this is a finding.'
  desc 'fix', 'If there is a finding, then MongoDB has not been installed via a package manager and may have been installed manually or not at all.

If MongoDB has not been installed via a package manager, verify that an organizational or site-specific document outlining the installation and upgrade procedures for software exists. Review this organizational or site-specific document to determine how and where MongoDB is to be installed on the system. Using this documentation, verify that MongoDB has been installed on the system prior to upgrading.

To verify the version of MongoDB Enterprise Server, run the following command in the directory where the MongoDB executable binary has been placed according to the organizational or site-specific documentation.

 cd %mongod binary directory%
 ./mongod --version

The output will show the version and architecture of the MongoDB Server binary similar to the following:

./mongod --version
db version v4.4.8
Build Info: {
    "version": "4.4.8",
    "gitVersion": "83b8bb8b6b325d8d8d3dfd2ad9f744bdad7d6ca0",
    "openSSLVersion": "OpenSSL 1.0.1e-fips 11 Feb 2013",
    "modules": [
        "enterprise"
    ],
    "allocator": "tcmalloc",
    "environment": {
        "distmod": "rhel70",
        "distarch": "x86_64",
        "target_arch": "x86_64"
    }
}

Verify that the version desired (what the upgraded version should be) matches what is shown the in output.

For example, if updated from MongoDB Enterprise Server v4.4.8 to v4.4.9, the output after the update would be similar to the above but the db version would reflect v4.4.9.

If the version is not what is expected, then remove the mongod binary from the system to prevent it from being used and consult the organizational or site-specific documents for further guidance.

Run the following commands as an operating system administrator to remove the MongoDB Enterprise Server binary from the system:

 cd mongod binary directory
 rm ./mongod'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55638r813926_chk'
  tag severity: 'medium'
  tag gid: 'V-252182'
  tag rid: 'SV-252182r813928_rule'
  tag stig_id: 'MD4X-00-006300'
  tag gtitle: 'SRG-APP-000454-DB-000389'
  tag fix_id: 'F-55588r813927_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
