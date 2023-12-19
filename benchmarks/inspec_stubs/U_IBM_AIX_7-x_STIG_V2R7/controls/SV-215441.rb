control 'SV-215441' do
  title 'The AIX operating system must accept and verify Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.

'
  desc 'check', 'Verify that the " bos.ahafs" package is installed:

# lslpp -l |grep bos.ahafs
                
  bos.ahafs                7.1.5.15  COMMITTED  Aha File System

If the "bos.ahafs" package is not installed, this is a finding.

Verify "pmfahotplugd" service is running:

# lssrc -s pmfahotplugd

If the " pmfahotplugd" service is not running, this is a finding.'
  desc 'fix', 'Install "bos.ahafs" fileset from the PowerSC MFA DVD using the following command (assuming that the DVD device is mounted to /dev/cd0):

# installp -aXYgd /dev/cd0 -e /tmp/install.log bos.ahafs

Start the "pmfahotplugd" service:

# startsrc-s pmfahotplugd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16639r294774_chk'
  tag severity: 'medium'
  tag gid: 'V-215441'
  tag rid: 'SV-215441r853493_rule'
  tag stig_id: 'AIX7-00-003205'
  tag gtitle: 'SRG-OS-000376-GPOS-00161'
  tag fix_id: 'F-16637r294775_fix'
  tag satisfies: ['SRG-OS-000376-GPOS-00161', 'SRG-OS-000377-GPOS-00162']
  tag 'documentable'
  tag legacy: ['SV-103039', 'V-92951']
  tag cci: ['CCI-001953', 'CCI-001954']
  tag nist: ['IA-2 (12)', 'IA-2 (12)']
end
