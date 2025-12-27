control 'SV-82527' do
  title 'The A10 Networks ADC must allow only the ISSM (or individuals or roles appointed by the ISSM) Root, Read Write, or Read Only privileges.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Administrators with Root, Read Write, or Read Only privileges can view the audit and system logs."
  desc 'check', 'Review the device configuration.

Enter the following command to view detailed information about the administrative accounts:
show admin detail

The output of this command will show the Access type, Privilege level, and GUI role, among other parameters. 

If persons other than the ISSM (or individuals or roles appointed by the ISSM) have Root, Read Write, or Read Only privileges, this is a finding.'
  desc 'fix', 'Do not configure accounts with Root, Read Write, or Read Only privileges for anyone other than the ISSM (or individuals or roles appointed by the ISSM).'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68597r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68037'
  tag rid: 'SV-82527r1_rule'
  tag stig_id: 'AADC-NM-000023'
  tag gtitle: 'SRG-APP-000090-NDM-000222'
  tag fix_id: 'F-74153r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
