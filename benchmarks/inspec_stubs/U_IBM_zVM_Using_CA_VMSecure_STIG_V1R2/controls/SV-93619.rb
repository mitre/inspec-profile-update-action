control 'SV-93619' do
  title 'IBM z/VM must remove or disable emergency accounts after the crisis is resolved or 72 hours.'
  desc "Emergency accounts are privileged accounts that are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.

Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by the organization's system administrators when network or normal logon/access is not available). Infrequently used accounts are not subject to automatic termination dates. Emergency accounts are accounts created in response to crisis situations, usually for use by maintenance personnel. The automatic expiration or disabling time period may be extended as needed until the crisis is resolved; however, it must not be extended indefinitely. A permanent account should be established for privileged users who need long-term maintenance accounts.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements."
  desc 'check', 'Ask the system administrator (SA) for a documented process to remove or disable emergency accounts after a crisis has been resolved or 72 hours.

If there is no documented process, this is a finding.

If there are emergency accounts enabled check date/time of resolution of last crisis event.

If date/time is greater than 72 hours, this is a finding.'
  desc 'fix', 'Develop a policy and process to remove or disable emergency accounts after a crisis has been resolved or 72 hours.

Ensure that all emergency accounts are disabled after a crisis has been resolved or 72 hours.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78499r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78913'
  tag rid: 'SV-93619r1_rule'
  tag stig_id: 'IBMZ-VM-000860'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-85663r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
