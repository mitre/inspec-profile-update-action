control 'SV-254000' do
  title 'The Juniper router must not be configured to have any feature enabled that calls home to the vendor.'
  desc 'Call home services will routinely send data such as configuration and diagnostic information to the vendor for routine or emergency analysis and troubleshooting. There is a risk that transmission of sensitive data sent to unauthorized persons could result in data loss or downtime due to an attack.'
  desc 'check', 'Verify the call home service is disabled on the device.

Verify [edit system] does NOT contain a phone-home hierarchy as shown:

[edit system]
host-name <hostname>;
:
<other system configuration>
:
phone-home {
    server https://<applicable URL>;
    rfc-compliant;
}

If a call home service is enabled, this is a finding.'
  desc 'fix', 'Configure the network device to disable the call home service or feature.

Delete the phone-home hierarchy under [edit system].

delete system phone-home
Note: Because the command is hidden, Junos will not autocomplete and "phone-home" must be explicitly, and correctly, spelled out.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57452r844031_chk'
  tag severity: 'medium'
  tag gid: 'V-254000'
  tag rid: 'SV-254000r844033_rule'
  tag stig_id: 'JUEX-RT-000280'
  tag gtitle: 'SRG-NET-000131-RTR-000083'
  tag fix_id: 'F-57403r844032_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
