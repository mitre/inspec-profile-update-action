control 'SV-233862' do
  title 'NSEC3 must be used for all DNSSEC signed zones.'
  desc %q(To ensure that resource records (RRs) associated with a query are really missing in a zone file and have not been removed in transit, the DNSSEC mechanism provides a means for authenticating the nonexistence of an RR. It generates a special RR called an NSEC (or NSEC3) RR that lists the RRTypes associated with an owner name as well as the next name in the zone file. It sends this special RR, along with its signatures, to the resolving name server. By verifying the signature, a DNSSEC-aware resolving name server can determine which authoritative owner name exists in a zone and which authoritative RRTypes exist at those owner names.

The Internet Engineering Task Force's (IETF's) design criteria consider DNS data to be public. Confidentiality is not one of the security goals of DNSSEC. DNSSEC is not designed to directly protect against denial-of-service threats but does so indirectly by providing message integrity and source authentication. An artifact of how DNSSEC performs negative responses allows a client to map all the names in a zone (zone walking). 

A zone that contains zone data the administrator does not want to be made public should use the NSEC3 RR option for providing authenticated denial of existence.

If DNSSEC is enabled for a server, the ability to verify a particular server that may attempt to update the DNS server actually exists. This is done through the use of NSEC3 records to provide an "authenticated denial of existence" for specific systems whose addresses indicate that they lie within a particular zone.)
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.  

1. Review the zone configuration and confirm that, if DNSSEC is enabled NSEC3 is used.  
2. Navigate to Data Management >> DNS >> Grid DNS Properties. Toggle Advanced Mode and review the "DNSSEC" tab.  
3. Ensure "Resource Record Type for Nonexistent Proof" is set to NSEC3.  
4. When complete, click "Cancel" to exit the "Properties" screen.  
5. Review zone data or use Global Search string ".". Type "Equals NSEC Record" to verify no undesired NSEC records exist. 

If NSEC records exist in an active zone, or NSEC3 is not configured, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Grid DNS Properties.  
2. Toggle Advanced Mode and edit the "DNSSEC" tab.  
3. Ensure "Resource Record Type for Nonexistent Proof" is set to NSEC3. 
4. Re-sign all DNSSEC zones that previously used NSEC.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37047r611106_chk'
  tag severity: 'medium'
  tag gid: 'V-233862'
  tag rid: 'SV-233862r621666_rule'
  tag stig_id: 'IDNS-8X-400004'
  tag gtitle: 'SRG-APP-000516-DNS-000084'
  tag fix_id: 'F-37012r611107_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
