control 'SV-214170' do
  title 'The Key Signing Key (KSK) rollover interval must be configured to no less than one year.'
  desc %q(The DNS root key is a cryptographic public-private key pair used for DNSSEC signing of the DNS root zone records. The root zone KSK serves as the anchor for the “chain of trust” that enables DNS resolvers to validate the authenticity of any signed data in the DNS. The integrity of the DNS depends on a secure root key. 
Rolling the KSK means generating a new cryptographic public and private key pair and distributing the new public component to parties who operate validating resolvers, including: Internet Service Providers; enterprise network administrators and other Domain Name System (DNS) resolver operators; DNS resolver software developers; system integrators; and hardware and software distributors who install or ship the root's "trust anchor." The KSK is used to cryptographically sign the Zone Signing Key (ZSK), which is used by the Root Zone Maintainer to DNSSEC-sign the root zone of the Internet's DNS.
Maintaining an up-to-date KSK is essential to ensuring DNSSEC-validating DNS resolvers continue to function following the rollover. Failure to have the current root zone KSK will mean that DNSSEC-validating DNS resolvers will be unable to resolve any DNS queries.
An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG covering the DS RR in the delegating parent. 

To prevent the impact of a compromised KSK, a delegating parent should also set the signature validity period for RRSIGs covering DS RRs in the range of a few days to one week. This re-signing does not require frequent rollover of the parent's ZSK, but scheduled ZSK rollover should still be performed at regular intervals.)
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Navigate to Data Management >> DNS >> Grid DNS properties. 

Toggle "Advanced Mode" and click on the "DNSSEC" tab. 

Validate the “Key-Signing Key Rollover Interval” is configured to a value of no less than one year.

If the “Key-Signing Key Rollover Interval” is configured to more than one year, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Grid DNS Properties.  
Toggle Advanced Mode and select the "DNSSEC" tab.  

Modify the “Key-Signing Key Rollover Interval” to a period of no less than one year.  

When complete, click "Save & Close" to save the changes and exit the "Properties" screen.  

Perform a service restart if necessary. 

Follow manual key rollover procedures and ensure changes are published to all applicable systems, including parent DNS systems.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15385r295776_chk'
  tag severity: 'medium'
  tag gid: 'V-214170'
  tag rid: 'SV-214170r612370_rule'
  tag stig_id: 'IDNS-7X-000230'
  tag gtitle: 'SRG-APP-000214-DNS-000079'
  tag fix_id: 'F-15383r295777_fix'
  tag 'documentable'
  tag legacy: ['V-68535', 'SV-83025']
  tag cci: ['CCI-001179']
  tag nist: ['SC-20 b']
end
