control 'SV-207556' do
  title 'The secondary name servers in a BIND 9.x implementation must be configured to initiate zone update notifications to other authoritative zone name servers.'
  desc "It is important to maintain the integrity of a zone file. The serial number of the SOA record is used to indicate to secondary name server that a change to the zone has occurred and a zone transfer should be performed. The serial number used in the SOA record provides the DNS administrator a method to verify the integrity of the zone file based on the serial number of the last update and ensure that all slave servers are using the correct zone file.
When a primary master name server notices that the serial number of a zone has changed, it sends a special announcement to all of the slave name servers for that zone. The primary master name server determines which servers are the slaves for the zone by looking at the list of NS records in the zone and taking out the record that points to the name server listed in the MNAME field of the zone's SOA record as well as the domain name of the local host.
When a secondary name server receives a NOTIFY announcement for a zone from one of its configured master name servers, it responds with a NOTIFY response. The response tells the master that the slave received the NOTIFY announcement so that the master can stop sending it NOTIFY announcements for the zone. Then the slave proceeds just as if the refresh timer for that zone had expired: it queries the master name server for the SOA record for the zone that the master claims has changed. If the serial number is higher, the slave transfers the zone.
The slave should next issue its own NOTIFY announcements to the other authoritative name servers for the zone. The idea is that the primary master may not be able to notify all of the slave name servers for the zone itself, since it's possible some slaves can't communicate directly with the primary master (they use another slave as their master). Older BIND 8 slaves don't send NOTIFY messages unless explicitly configured to do so."
  desc 'check', 'If this is a master name server, this is Not Applicable.

On a secondary name server, verify that the global notify is disabled. The global entry for the name server is under the “Options” section and notify should be disabled at this section.

Inspect the "named.conf" file for the following:

options {
notify no;
};

If the "notify" statement is missing, this is a finding.
If the "notify" statement is set to "yes", this is a finding.

Verify that zones for which the secondary server is authoritative is configured to notify other authorized secondary name servers when a zone file update has been received from the master name server for the zone.
Each zone has its own Zone section.

Inspect the "named.conf" file for the following:

zone example.com {
notify explicit;
also-notify { <ip_address>; | <address_match_list>; };

If an "address match list" is used, verify that each ip address listed is an authorized secondary name server for that zone.

If the “notify explicit” statement is missing, this is a finding.
If the "also-notify" statement is missing, this is a finding.
If the "also-notify" statement is configured to notify name servers that are not authorized for that zone, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Configure the "notify" sub statement in the "options" statement block to "no":

options { 
notify no;
};

Configure the “notify explicit” and "also-notify" sub statements in the zone statement block to limit zone transfer notifications to authorized secondary name servers:

zone example.com {
notify explicit;
also-notify { <ip_address>; | <address_match_list>; };

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7811r283722_chk'
  tag severity: 'low'
  tag gid: 'V-207556'
  tag rid: 'SV-207556r612253_rule'
  tag stig_id: 'BIND-9X-001058'
  tag gtitle: 'SRG-APP-000516-DNS-000088'
  tag fix_id: 'F-7811r283723_fix'
  tag 'documentable'
  tag legacy: ['SV-87035', 'V-72411']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
