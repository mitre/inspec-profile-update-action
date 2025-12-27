control 'SV-254712' do
  title 'The BlackBerry Enterprise Mobility Server (BEMS) must protect the confidentiality and integrity of transmitted information through the use of an approved TLS version.'
  desc 'Preventing the disclosure of transmitted information requires that the application server take measures to employ some form of cryptographic mechanism to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

Transmission of data can take place between the application server and a large number of devices/applications external to the application server. Examples are a web client used by a user, a backend database, a log server, or other application servers in an application server cluster.

If data is transmitted unencrypted, the data then becomes vulnerable to disclosure. The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information.

FIPS 140-2 approved TLS versions include TLS V1.0 or greater.

TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Verify BEMS has been configured to use only approved versions of TLS as follows:

1. Find the xml file "jetty.xml" located in the BEMS install directory on the BEMS host Windows server. 
2. Find the "ExcludeProtocols" field.
3. Verify if unauthorized versions of SSL and TLS are listed in the "jetty.xml" file.
 <Set name="ExcludeProtocols">
    <Array type="java.lang.String">
    <Item>TLSv1</Item>
    <Item>TLSv1.1</Item>
    <Item>SSL</Item>
    <Item>SSLv2</Item>
    <Item>SSLv2Hello</Item>
    <Item>SSLv3</Item>

If BEMS has not been configured to use only approved versions of TLS and the Exclude file does not include all of the above TLS and SSL protocols, this is a finding.'
  desc 'fix', 'Configure BEMS to use approved versions of TLS.

1. Find the xml file "jetty.xml" located in the BEMS install directory on the BEMS host Windows server. 
2. Find the "ExcludeProtocols" field and add all unauthorized versions or SSL and TLS.
    <Set name="ExcludeProtocols">
    <Array type="java.lang.String">
    <Item>TLSv1</Item>
    <Item>TLSv1.1</Item>
    <Item>SSL</Item>
    <Item>SSLv2</Item>
    <Item>SSLv2Hello</Item>
    <Item>SSLv3</Item>
3. Save the file.
4. Restart the BEMS server.'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58323r861859_chk'
  tag severity: 'medium'
  tag gid: 'V-254712'
  tag rid: 'SV-254712r861861_rule'
  tag stig_id: 'BEMS-03-011400'
  tag gtitle: 'SRG-APP-000439-AS-000155'
  tag fix_id: 'F-58269r861860_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
