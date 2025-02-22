control 'SV-228837' do
  title 'The Palo Alto Networks security platform must only enable User-ID on trusted zones.'
  desc 'User-ID can use Windows Management Instrumentation (WMI) probing as a method of mapping users to IP addresses. If this is used, the User-ID Agent will send a probe to each learned IP address in its list to verify that the same user is still logged in. The results of the probe will be used to update the record on the agent and then be passed on to the firewall.  WMI probing is a Microsoft feature that collects user information from Windows hosts and contains a username and encrypted password hash of a Domain Administrator account.

If User-ID and WMI probing are enabled on an external untrusted zone (such as the Internet), probes could be sent outside the protected network, resulting in an information disclosure of the User-ID Agent service account name, domain name, and encrypted password hash.  This information has the potential to be cracked and exploited by an attacker to gain unauthorized access to protected resources.  For this important reason, User-ID should never be enabled on an untrusted zone.'
  desc 'check', 'To verify that Windows Management Instrumentation (WMI) probing is unchecked for all untrusted zones:

Go to Network >> Zones, view each zone.
If the Zone is untrusted and if the UserID Enabled column is checked, this is a finding.

Go to Network >> Network Profiles >> Interface Mgmt
View the configured Interface Management Profiles.
Note which Interface Management Profiles have the "User-ID" field enabled (checked).
Go Network >> Interfaces
Each interface is listed; note that there are four tabs - Ethernet, VLAN, Loopback, and Tunnel.  Each type can have an Interface Management Profile applied to it.

View each interface that is in an untrusted security zone; if each one has no Interface Management Profile applied, this is not a finding.

If each interface in an untrusted security zone has an Interface Management Profile applied to it, the Interface Management Profile must be one that does not have User-ID enabled; if it does, this is a finding.'
  desc 'fix', 'To deny User-ID on untrusted zones:
Go to Network >> Zones, select the name of the zone.
If the Zone is untrusted, In the Zone window, deselect (uncheck) the Enable User Identification check box.
Select "OK".
Go to Network >> Network Profiles >> Interface Mgmt
Select "Add" to create a new profile or select the name of a profile to edit it.
In the "Interface Management Profile" window, deselect the "User-ID" check box if it is selected.
Select "OK".

Note: This action precludes that particular Interface Management Profile from supporting User-ID.

An interface does not need an Interface Management Profile to operate; only to be managed on that interface.
Go Network >> Interfaces
Each interface is listed; note that there are four tabs - Ethernet, VLAN, Loopback, and Tunnel.
Each type can have an Interface Management Profile applied to it.
View each interface that is in an untrusted security zone; if it has an Interface Management Profile applied to it, the Interface Management Profile must be one that does not have User-ID enabled.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31072r513806_chk'
  tag severity: 'medium'
  tag gid: 'V-228837'
  tag rid: 'SV-228837r557387_rule'
  tag stig_id: 'PANW-AG-000035'
  tag gtitle: 'SRG-NET-000131-ALG-000085'
  tag fix_id: 'F-31049r513807_fix'
  tag 'documentable'
  tag legacy: ['V-62557', 'SV-77047']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
