control 'SV-104519' do
  title 'Symantec ProxySG must support organizational requirements to conduct backups of system level information contained in the ProxySG when changes occur or weekly, whichever is sooner.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Symantec ProxySG supports backups natively. Verify that backups are being stored remotely.

1. Check with the Symantec ProxySG administrator to determine what their strategy is for backups.
2. Log on to the Web Management Console.
3. Click Configuration >> General >> Archive >> Archive Storage.
4. Confirm that there are entries in the "Remote Upload" fields (Host, Path, Username).

If Symantec ProxySG does not support organizational requirements to conduct backups of system level information contained in the Symantec ProxySG when changes occur or weekly, whichever is sooner, this is a finding.'
  desc 'fix', 'Configure backups for remote storage as follows.

1. Log on to the Web Management Console.
2. Click Configuration >> General >> Archive >> Archive Storage.
3. Provide the correct entries in the "Remote Upload" fields for an available remote backup storage server (Protocol, Host, Path, Username).
4. Click "Apply".

Note: Please see Chapter 5: Backing Up the Configuration in the ProxySG Administration Guide for complete details.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94689'
  tag rid: 'SV-104519r1_rule'
  tag stig_id: 'SYMP-NM-000190'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-100807r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
