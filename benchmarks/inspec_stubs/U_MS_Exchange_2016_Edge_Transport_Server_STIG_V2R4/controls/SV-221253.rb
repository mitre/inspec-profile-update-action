control 'SV-221253' do
  title 'Exchange must render hyperlinks from email sources from non-.mil domains as unclickable.'
  desc "Active hyperlinks within an email are susceptible to attacks of malicious software or malware. The hyperlink could lead to a malware infection or redirect the website to another fraudulent website without the user's consent or knowledge. 

Exchange does not have a built-in message filtering capability. DoD Enterprise Email (DEE) has created a custom resolution to filter messages from non-.mil users that have hyperlinks in the message body. The hyperlink within the messages will be modified, preventing end users from automatically clicking links."
  desc 'check', %q(Note: If using a DoD-approved protection mechanism such as Cloud Based Internet Isolation (CBII), Bromium, Email Gateway spamming device, such as Enterprise Email Security Gateway (EEMSG), or other approved email sanitization solution that protects against untrusted URLs embedded in email, this is not applicable.

Note: If system is on SIPRNet, this is not applicable.

Review the Email Domain Security Plan (EDSP).

Determine the name of the Transport Agent. 

Open the Windows PowerShell console and enter the following command:

Get-TransportAgent -Name 'customAgent' | FL

If the value does not return "customAgent", this is a finding.

Note: "customAgent" is the name of the custom agent developed to render hyperlink email sources from non .mil domains as unclickable.)
  desc 'fix', 'Update the EDSP to reflect the name of the Transport Agent.

Contact the DISA Enterprise Email Service Desk at disa.tinker.eis.mbx.dod-enterprise-services-service-desk@mail.mil and request the Agent and installation procedures.

or

Contact DEE Engineering PMO and request the Agent and installation procedures.'
  impact 0.7
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22968r811175_chk'
  tag severity: 'high'
  tag gid: 'V-221253'
  tag rid: 'SV-221253r811176_rule'
  tag stig_id: 'EX16-ED-000570'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22957r411886_fix'
  tag 'documentable'
  tag legacy: ['SV-95297', 'V-80587']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
