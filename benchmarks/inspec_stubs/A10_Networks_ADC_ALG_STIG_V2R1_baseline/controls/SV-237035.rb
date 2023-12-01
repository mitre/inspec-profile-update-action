control 'SV-237035' do
  title 'The A10 Networks ADC must not have unnecessary scripts installed.'
  desc 'Information systems are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the device. Unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The A10 Networks ADC can use a TCL-based scripting language called aFleX. Scripts used by an A10 Networks ADC must be documented so that Administrative and Security personnel understand them.'
  desc 'check', 'Review the ALG configuration to determine if any aFleX scripts are used on the device.

The following command displays all of the configured aFleX scripts:
show aflex all

If any scripts are present, ask the Administrator for documentation of each script. 

If no documents can be provided explaining the script and showing where the ISSM or other responsible Security personnel acknowledged the script is being used, this is a finding.'
  desc 'fix', 'Do not load any unnecessary aFleX scripts on the device.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40254r639550_chk'
  tag severity: 'medium'
  tag gid: 'V-237035'
  tag rid: 'SV-237035r639552_rule'
  tag stig_id: 'AADC-AG-000034'
  tag gtitle: 'SRG-NET-000131-ALG-000085'
  tag fix_id: 'F-40217r639551_fix'
  tag 'documentable'
  tag legacy: ['SV-82453', 'V-67963']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
