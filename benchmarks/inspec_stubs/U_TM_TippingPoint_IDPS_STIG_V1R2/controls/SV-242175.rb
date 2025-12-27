control 'SV-242175' do
  title 'The Trend Micro TPS must immediately use updates made to policy filters, rules, signatures, and anomaly analysis algorithms for traffic detection and prevention functions which are all contained in the Digital Vaccine (DV) updates.'
  desc 'Information flow policies regarding dynamic information flow control include, for example, allowing or disallowing information flows based on changes to the PPSM CAL, vulnerability assessments, or mission conditions. Changing conditions include changes in the threat environment and detection of potentially harmful or adverse events.

Changes to the TPS must take effect when made by an authorized administrator and the new configuration is put in place or committed, including upon restart or the application or reboot of the system. With some devices, the changes take effect as the configuration is changed, while with others, the new configuration must be submitted to the device. In any case, the behavior of the TPS must immediately be affected to reflect the configuration change.'
  desc 'check', '1. In the Trend Micro SMS interface, go to the "Profiles" and then "Digital Vaccines". 
2. Check the latest DV version that is downloaded/imported and is active. Go the Trend Micro support system located here: https://tmc.tippingpoint.com/TMC/Releases
3. Under Digital Vaccines, select the DV major version (3.2.0 currently).
4. Ensure the latest signature release is the current one that is applied to the SMS and is active to all TPS systems in the network. 

If the latest one is not applied as the Active DV version, this is a finding.'
  desc 'fix', '1. In the Trend Micro SMS interface, go to the "Profiles" and then "Digital Vaccines". 
2. Check the latest DV version that is downloaded/imported and is active. Go the Trend Micro support system located here: https://tmc.tippingpoint.com/TMC/Releases 
3. Under Digital Vaccines, select the DV major version (3.2.0 currently).
4. Download the latest signature file (e.g. SIG_3.2.0_9404.pkg).
5. Read the EULA acceptance notice, then select Accept. 
6. Under an approved network change window, go back to the SMS, Profiles, and Digital Vaccines. 
7. Select "import", then select the file downloaded from the TMC site. 
8. Once prompted, select distribute to all TPS devices in the network.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45450r710066_chk'
  tag severity: 'medium'
  tag gid: 'V-242175'
  tag rid: 'SV-242175r710068_rule'
  tag stig_id: 'TIPP-IP-000090'
  tag gtitle: 'SRG-NET-000019-IDPS-00187'
  tag fix_id: 'F-45408r710067_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
