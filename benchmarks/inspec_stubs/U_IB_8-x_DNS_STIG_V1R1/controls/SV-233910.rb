control 'SV-233910' do
  title "The validity period for the Resource Record Signatures (RRSIGs) covering the Delegation Signer (DS) RR for a zone's delegated children must be no less than two days and no more than one week."
  desc "The best way for a zone administrator to minimize the impact of a key compromise is by limiting the validity period of RRSIGs in the zone and in the parent zone. This strategy limits the time during which an attacker can take advantage of a compromised key to forge responses. An attacker that has compromised a Zone Signing Key (ZSK) can use that key only during the Key Signing Key's (KSK's) signature validity interval. An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG covering the DS RR in the delegating parent. These validity periods should be short, which will require frequent re-signing.

To prevent the impact of a compromised KSK, a delegating parent should set the signature validity period for RRSIGs covering DS RRs in the range of a few days to one week. This re-signing does not require frequent rollover of the parent's ZSK, but scheduled ZSK rollover should still be performed at regular intervals."
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.  

1. Navigate to Data Management >> DNS >> Grid DNS properties. 
2. Toggle Advanced Mode, click on "DNSSEC" tab, and review the "Signature Validity" setting. 
3. Validate that the Signature Validity is configured for a range of no less than two days and no more than one week. 
4. When complete, click "Cancel" to exit the "Properties" screen.

If the Signature Validity period is less than two days or greater than one week, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Grid DNS properties. 
2. Toggle Advanced Mode, click on "DNSSEC" tab, and edit the "Signature Validity" setting to a period between two days and one week.  
3. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
4. Any zones that used an incorrect value should perform a ZSK rollover to update the inception and expiration dates with the new value.  
5. Navigate to Data Management >> DNS and select the "Zones" tab.  
6. Using the zone selection check boxes and the DNSSEC drop-down menu, select "Rollover Zone-Signing Key".
7. When prompted, select "Roll Over".
8. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37095r611250_chk'
  tag severity: 'medium'
  tag gid: 'V-233910'
  tag rid: 'SV-233910r621666_rule'
  tag stig_id: 'IDNS-8X-700005'
  tag gtitle: 'SRG-APP-000214-DNS-000079'
  tag fix_id: 'F-37060r611251_fix'
  tag 'documentable'
  tag cci: ['CCI-001179']
  tag nist: ['SC-20 b']
end
