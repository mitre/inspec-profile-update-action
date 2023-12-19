control 'SV-233898' do
  title 'The Infoblox system must require devices to reauthenticate for each zone transfer and dynamic update request connection attempt.'
  desc 'Without reauthenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of devices, including but not limited to the following other situations:
(i) When authenticators change;
(ii) When roles change;
(iii) When security categories of information systems change;
(iv) After a fixed period of time; or
(v) Periodically.

DNS does perform server authentication when DNSSEC is used, but this authentication is transactional in nature (each transaction has its own authentication performed). Therefore, this requirement is applicable for every server-to-server transaction request.'
  desc 'check', '1. Navigate to Data Management >> DNS >> Zones tab.  
2. Review each zone by clicking "Edit" and inspecting the "Name Servers" tab.  
3. If all entries in the "Type" column are configured as "Grid", this check is Not Applicable.  
4. Verify that each zone containing non-Grid name servers is further verified by inspection of the "Zone Transfers" tab and configuration of TSIG Access Control Entry (ACE). 
5. When complete, click "Cancel" to exit the "Properties" screen. 

If there is a non-Grid system that uses zone transfers but does not have a TSIG key, this is a finding.'
  desc 'fix', 'Note that TSIG relies on both key and time synchronization. TSIG will fail if the local clocks on both names are not synchronized. 

1. Navigate to Data Management >> DNS >> Zones tab. 
2. Select a zone and click "Edit". Click on the "Zone Transfers" tab and click "Override" for the "Allow Zone Transfers to" section.  
3. Use the radio button to select "Set of ACEs" and the "Add" drop-down to configure a TSIG key.  
4. It is important to verify that both the Infoblox and other DNS server have the identical TSIG configuration.  
5. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
6. Perform a service restart if necessary.
7. Verify zone transfers are operational after configuration of TSIG.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37083r611214_chk'
  tag severity: 'medium'
  tag gid: 'V-233898'
  tag rid: 'SV-233898r621666_rule'
  tag stig_id: 'IDNS-8X-500001'
  tag gtitle: 'SRG-APP-000390-DNS-000048'
  tag fix_id: 'F-37048r611215_fix'
  tag 'documentable'
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
