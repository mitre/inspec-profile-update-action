control 'SV-256077' do
  title 'The Riverbed NetProfiler must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.'
  desc "To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, it must be documented and approved.

NOTE: Configuration of the network firewall is out of scope for this STIG. However, the network firewall must be configured to ONLY allow the following ports to the Riverbed NetProfiler.
- TCP/22 – (SSH) Used for secure shell access to SteelCentral software components and for the appliance to obtain information from servers via scripts.
- TCP/443 – Used to secure web-based management interfaces.
- TCP/8443 – Used for exchange of encryption certificates between SteelCentral products.
- TCP/41017 – Used for encrypted communication between NetProfiler and Flow Gateway, NetShark, and AppResponse appliances.
- TCP/5432 – (ODBC) Enable this port if plans are to enable other applications' access to the NetProfiler internal database via ODBC.
- TCP/42999 – Enable traffic on this port if the intent is to use the NetProfiler user identification feature with a Microsoft Active Directory domain controller.
- UDP/123 – (NTP) Used for synchronization of time between a Flow Gateway and NetProfiler.
- UDP/161 – (SNMP) Used by the NetProfiler or Flow Gateway to obtain interface information from switches, routers, firewalls, SteelHeads, and any sFlow or Netflow sources. Also, management systems use this port to read the SteelCentral product Management Information Base (MIB).
- Vulnerability scanner ports – Use of the NetProfiler vulnerability scan feature requires allowing traffic on the port the SteelCentral product uses to access the vulnerability scanner server. Obtain the vulnerability scanner server addresses and port numbers from the administrator of those systems. The default ports are:
   - Nessus: 1241
   - nCircle: 443
   - Rapid7: 3780
   - Qualys: Requires external https access to qualysapi.qualys.com (Note: This is separate from qualysguard.qualys.com.)
   - Foundstone: 3800"
  desc 'check', 'Work with the site representative to identify unnecessary and/or nonsecure functions, ports, protocols, and/or services that are enabled.

If unnecessary and/or nonsecure functions, ports, protocols, and/or services are enabled, this is a finding.'
  desc 'fix', 'Remove unused or unnecessary services that are not being used.

Example: If the AUX port is not being used, go to the Configuration >> General Settings page, AUX interface configuration section, and deselect the "Configure AUX Interface" option. This disables the AUX interface.

If any static routes were added for the configuration that are no longer needed, remove them in the Static Routes section.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59751r882737_chk'
  tag severity: 'medium'
  tag gid: 'V-256077'
  tag rid: 'SV-256077r882739_rule'
  tag stig_id: 'RINP-DM-000026'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-59694r882738_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
