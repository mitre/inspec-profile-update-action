control 'SV-240522' do
  title 'The SLES for vRealize must verify correct operation of all security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Verify the SLES for vRealize produces audit records by running the following command to determine the current status of the "auditd" service:

# service auditd status

If the service is enabled, the returned message must contain the following text:

Checking for service auditd                running

If the service is not "running", this is a finding.'
  desc 'fix', 'Enable the "auditd" service by performing the following commands:

# chkconfig auditd on
# service auditd start'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43755r671305_chk'
  tag severity: 'medium'
  tag gid: 'V-240522'
  tag rid: 'SV-240522r852583_rule'
  tag stig_id: 'VRAU-SL-001350'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-43714r671306_fix'
  tag 'documentable'
  tag legacy: ['SV-100471', 'V-89821']
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
