control 'SV-228670' do
  title 'The Palo Alto Networks security platform must not use SNMP Versions 1 or 2.'
  desc 'SNMP Versions 1 and 2 are not considered secure. Without the strong authentication and privacy that is provided by the SNMP Version 3 User-based Security Model (USM), an unauthorized user can gain access to network management information used to launch an attack against the network.  SNMP Versions 1 and 2 cannot authenticate the source of a message nor can they provide encryption. Without authentication, it is possible for nonauthorized users to exercise SNMP network management functions. It is also possible for nonauthorized users to eavesdrop on management information as it passes from managed systems to the management system.'
  desc 'check', 'Go to Device >> Setup >> Operations; in the Miscellaneous pane, select SNMP Setup.
In the SNMP Setup window, check if SNMP V3 is selected.  
If V3 is not selected, this is a finding.

Go to Device >> Server Profiles >> SNMP Trap.
View the list of configured SNMP servers; if the Version is not "v3", this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Operations; in the Miscellaneous pane, select SNMP Setup.
In the SNMP Setup window, complete the required fields.
For the Version, select V3.
Configure a view and assign it to a user.
In the upper half of the SNMP Setup window, select "Add".
In the Views window, complete the required fields; obtain the values for the OID and Mask fields from product documentation or vendor support.
In the Option field, select "include". 
Select "OK".
In the lower half of the SNMP Setup window, select "Add".
Complete the required fields.
Select "OK".
Obtain the engineID of the Palo Alto device by issuing an SNMPv3 GET from the management workstation against the OID of the Palo Alto device.
Configure the SNMPv3 Trap Server profile; go to Device >> Server Profiles >> SNMP Trap; select "Add".
In the SNMP Trap Server Profile window, complete the required fields. 
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.7
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30905r513613_chk'
  tag severity: 'high'
  tag gid: 'V-228670'
  tag rid: 'SV-228670r513615_rule'
  tag stig_id: 'PANW-NM-000118'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-30882r513614_fix'
  tag 'documentable'
  tag legacy: ['SV-77257', 'V-62767']
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
