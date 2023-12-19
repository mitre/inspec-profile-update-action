control 'SV-228838' do
  title 'The Palo Alto Networks security platform must disable WMI probing if it is not used.'
  desc 'User-ID can use Windows Management Instrumentation (WMI) probing as a method of mapping users to IP addresses. If this is used, the User-ID Agent will send a probe to each learned IP address in its list to verify that the same user is still logged in. The results of the probe will be used to update the record on the agent and then be passed on to the firewall.  WMI probing is a Microsoft feature that collects user information from Windows hosts, and contains a username and encrypted password hash of a Domain Administrator account.

WMI probing on external/untrusted zones can result in the User-ID agent sending WMI probes to external/untrusted hosts.  An attacker can capture these probes and obtain the username, domain name and encrypted password hash associated with the User-ID account. If WMI probing is not used as a method of user to IP address mapping, it must be disabled.'
  desc 'check', 'Ask the Administrator if User-ID uses WMI Probing; if it does, this is not a finding.

Go to Device >> User Identification
On the "User Mapping" tab, in the "Palo Alto Networks User ID Agent" pane, view the "Enable Probing" check box. If it is selected, this is a finding.'
  desc 'fix', 'To disable WMI probing if it is not used:
Go to Device >> User Identification
On the "User Mapping" tab, in the "Palo Alto Networks User ID Agent" pane, view the "Enable Probing" check box.
If it is selected, select the "Edit" icon in the upper-right corner of the pane.
In the "Palo Alto Networks User ID Agent Setup" window, in the "Client Probing" tab, deselect the "Enable Probing" check box.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31073r513809_chk'
  tag severity: 'medium'
  tag gid: 'V-228838'
  tag rid: 'SV-228838r557387_rule'
  tag stig_id: 'PANW-AG-000036'
  tag gtitle: 'SRG-NET-000131-ALG-000085'
  tag fix_id: 'F-31050r513810_fix'
  tag 'documentable'
  tag legacy: ['V-62559', 'SV-77049']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
