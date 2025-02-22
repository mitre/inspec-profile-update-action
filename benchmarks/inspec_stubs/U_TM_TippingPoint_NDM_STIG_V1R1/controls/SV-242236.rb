control 'SV-242236' do
  title 'The TippingPoint SMS must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'In the SMS client, ensure the SMS and TPS have disabled all unnecessary and insecure protocols. 

1. For SMS, click Admin and Management. 
2. Ensure only Ping is enabled and the SMS is in FIPS Mode. If any other services are enabled or if the SMS is not in FIPS mode, this is a finding.
3. For TPS, click Devices, All Devices, and the subject device hostname.
4. Click Device Configuration and select Services. Ensure only TLS 1.2 is enabled. 
5. Under FIPS Settings ensure the FIPS Mode is selected. If any other services are enabled or if the TPS is not in FIPS mode, this is a finding.'
  desc 'fix', 'In the SMS client, ensure the SMS and TPS have disabled all unnecessary and insecure protocols. 

1. For SMS, click Admin and Management. 
2. Uncheck SSH, HTTPS, and TAXII. Ensure only Ping is checked.
3. Click edit on FIPS Mode. 
4. Under an approved change window only, enable FIPS Crypto Core. This will cause a reboot; only do this when authorized.
5. For TPS, click Devices, All Devices, and the subject device hostname. 
6. Click Device Configuration and select Services. 
7. Uncheck SSH, TLS 1.0 and TLS 1.1. Only HTTPS should be selected. 
8. Under FIPS Settings ensure the FIPS Mode is selected. This should also be done in an approved change window, as a reboot will be triggered.'
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45511r710713_chk'
  tag severity: 'high'
  tag gid: 'V-242236'
  tag rid: 'SV-242236r710715_rule'
  tag stig_id: 'TIPP-NM-000200'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-45469r710714_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
