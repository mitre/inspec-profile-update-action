control 'SV-225237' do
  title 'Remoting Services TCP channels must utilize authentication and encryption.'
  desc 'Note: Microsoft recommends using the Windows Communication Framework (WCF) rather than .Net remoting. New development projects should refrain from using .Net remoting capabilities whenever possible.

.NET remoting provides the capability to build widely distributed applications. The application components may reside all on one computer or they may be spread out across the enclave. .NET client applications can make remoting calls to use objects in other processes on the same computer or on any other computer that is reachable over the network. .NET remoting can also be used to communicate with other application domains within the same process.  Remoting is achieved via the exposure of endpoints that can be used to establish remote connectivity.

Normally when application code attempts to access a protected resource, a stack walk is performed to ensure that all stack frames have permission to access the resource. However, with .Net 4.0, when a call is made on a remote object, this stack walk is not performed across the remoting boundary. The .Net remoting infrastructure requires FullTrust permission to execute on either the client or the server. 

Due to the fact that FullTrust permission is required, Remoting endpoints should be authenticated and encrypted in order to protect the system and the data. 

Microsoft provides 3 different "channels" that are used for remoting.  They are HTTP, TCP and IPC.

Any unauthorized use of a remoting application provides unauthorized access with FullTrust permissions to the system. This can potentially result in a loss of system integrity or confidentiality.'
  desc 'check', %q(Check the machine.config and the [application executable name].exe.config configuration files. 

For 32 bit systems, the "machine.config" file is contained in the following folder. %SYSTEMROOT%\Microsoft.NET\Framework\v4.0.30319\Config 

For 64 bit systems, the "machine.config" file is contained in the following folder. %SYSTEMROOT%\Microsoft.NET\Framework64\v4.0.30319\Config.

Microsoft specifies locating the application config file in the same folder as the application executable (.exe) file. However, the developer does have the capability to specify a different location when the application is compiled.  Therefore, if the config file is not found in the application home folder, a search of the system is required. If the [application name].exe.config file is not found on the system, then only a check of the machine.config file is required.

Sample machine/application config file:

<application name=“remoteserver”> 
  <service> 
    <activated type=“sample.my.object, myobjects”/> 
  </service> 
  <channels> 
    <channel ref=“tcp server” port=“6134”/> 
  </channels> 
</application>

<serverProviders>
  <provider ref="wsdl" />
  <formatter ref="soap" typeFilterLevel="Full" /> 
  <formatter ref="binary" typeFilterLevel="Full" /> 
</serverProviders> 

Microsoft provides 3 "channels" that are used for remoting connectivity.  They are the HTTP, TCP, and IPC channels.  The channel that is used is specified via the <channels> element in the config file.  

TCP channel example:
<channel ref=“tcp” port=“6134” secure="true"/> 

The TCP Channel provides encryption and message integrity when the 'secure' flag is set to true as shown in the above example.

If the secure flag is not set to "true" for the TCP channel, this is a finding.)
  desc 'fix', 'Ensure encryption and message integrity are used for TCP remoting channels.

TCP remoting connections are protected via the secure=true configuration parameter.
<channels>
   <channel ref="tcp" secure="true" />
</channels>

Include the secure="true" flag in the channel ref parameter of the machine.config and [application name].exe.config file if the [application name].exe.config file exists on the system.'
  impact 0.5
  ref 'DPMS Target Microsoft DotNet Framework 4-0'
  tag check_id: 'C-26936r468026_chk'
  tag severity: 'medium'
  tag gid: 'V-225237'
  tag rid: 'SV-225237r615940_rule'
  tag stig_id: 'APPNET0071'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-26924r468027_fix'
  tag 'documentable'
  tag legacy: ['SV-42341', 'V-32025']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
