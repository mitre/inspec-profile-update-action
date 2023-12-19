control 'SV-257171' do
  title 'The macOS system must shut down by default upon audit failure (unless availability is an overriding concern).'
  desc 'The audit service should shut down the computer if it is unable to audit system events. Once audit failure occurs, user and system activity are no longer recorded and malicious activity could go undetected. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend on the nature of the failure mode.

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

(i) If the failure was caused by the lack of audit record storage capacity, the operating system must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the operating system must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Verify the macOS system is configured to shut down upon audit failure with the following command:

/usr/bin/sudo /usr/bin/grep ^policy /etc/security/audit_control | /usr/bin/grep ahlt

If there is no result, this is a finding.'
  desc 'fix', %q(Configure the macOS system to shut down upon audit failure by editing the "/etc/security/audit_control" file and updating the policy value to include "ahlt" with the following command:

/usr/bin/sudo /usr/bin/sed -i.bak '/^policy/ s/$/,ahlt/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s)
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60856r905144_chk'
  tag severity: 'medium'
  tag gid: 'V-257171'
  tag rid: 'SV-257171r905146_rule'
  tag stig_id: 'APPL-13-001010'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-60797r905145_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
