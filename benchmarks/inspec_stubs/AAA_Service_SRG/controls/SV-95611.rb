control 'SV-95611' do
  title 'AAA Services used for 802.1x must be configured to use secure Extensible Authentication Protocol (EAP), such as EAP-TLS, EAP-TTLS, and PEAP.'
  desc 'Additional new EAP methods/types are still being proposed. However, the three being considered secure are EAP-TLS, EAP-TTLS, and PEAP. PEAP is the preferred EAP type to be used in DoD for its ability to support a greater number of operating systems and its capability to transmit statement of health information, per NSA NAC study.

Lightweight EAP (LEAP) is a CISCO proprietary protocol providing an easy-to-deploy one-password authentication. LEAP is vulnerable to dictionary attacks. A "man in the middle" can capture traffic, identify a password, and then use it to access a WLAN. LEAP is inappropriate and does not provide sufficient security for use on DOD networks.

EAP-MD5 is functionally similar to CHAP and is susceptible to eavesdropping because the password credentials are sent as a hash (not encrypted). In addition, server administrators would be required to store unencrypted passwords on their servers violating other security policies. EAP-MD5 is inappropriate and does not provide sufficient security for use on DOD networks.'
  desc 'check', 'Verify AAA Services used for 802.1x are configured to use secure EAP. Currently acceptable secure protocols are EAP-TLS, EAP-TTLS, and PEAP.

If AAA Services used for 802.1x are not configured to use secure EAP, this is a finding.'
  desc 'fix', 'Configure AAA Services used for 802.1x to use secure EAP, such as EAP-TLS, EAP-TTLS, and PEAP.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80639r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80901'
  tag rid: 'SV-95611r1_rule'
  tag stig_id: 'SRG-APP-000516-AAA-000440'
  tag gtitle: 'SRG-APP-000516-AAA-000440'
  tag fix_id: 'F-87757r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
