control 'SV-258469' do
  title 'The Google Android 13 BYOAD and DOD enterprise must be configured to limit access to only AO-approved, corporate-owned enterprise IT resources.'
  desc 'Note: IT resources includes DOD networks and applications (for example, DOD email).

The System Administrator must have the capability to limit access of the BYOAD to DOD networks and DOD IT resources based on mission needs and risk. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DOD sensitive information. The AO should document networks, IT resources, and enterprise applications that BYOAD can access.

Examples of EMM security controls are as follows:
1. Device access restrictions: Restrict or isolate access based on the devices access type (i .e., from the internet), authentication type (e.g., password), credential strength, etc.
2. User and device activity monitoring: Configured to detect anomalous activity, malicious activity, and unauthorized attempts to access DOD information.
3. Device health tracking: Monitor device attestation, health, and agents reporting compromised applications, connections, intrusions, and/or signatures.

Reference: DOD policy "Use of Non-Government Mobile Devices" (3.b.(2)ii).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM system and DOD enterprise have been configured to limit the Google Android 13 BYOAD access to only AO-approved enterprise IT resources. The exact procedure will depend on the EMM system used and IT resources at the site.

If the EMM system and DOD enterprise have not been configured to limit Google Android 13 BYOAD access to only AO-approved enterprise IT resources, this is a finding.'
  desc 'fix', 'Configure the EMM system and DOD enterprise to limit the Google Android 13 BYOAD access to only AO-approved enterprise IT resources. The exact procedure will depend on the EMM system used and IT resources at the site.'
  impact 0.7
  ref 'DPMS Target Google Android 13 MDFPP 3.3 BYOAD'
  tag check_id: 'C-62209r929221_chk'
  tag severity: 'high'
  tag gid: 'V-258469'
  tag rid: 'SV-258469r929223_rule'
  tag stig_id: 'GOOG-13-801100'
  tag gtitle: 'PP-BYO-000110'
  tag fix_id: 'F-62118r929222_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
