control 'SV-254118' do
  title 'Nutanix AOS must configure network traffic segmentation when using Disaster Recovery Services.'
  desc 'The application server consists of the management interface and hosted applications, as well as cluster management functions. Separating the management interface from hosted applications prevents nonprivileged users from having visibility to functions not available to the user. Isolating cluster management functions ensures that cluster housekeeping tasks such as disaster recovery, replication, etc. function on their own network segment away from production traffic.

Application server management functionality includes functions necessary to administer the application server and requires privileged access via one of the accounts assigned to a management role. The hosted application and hosted application functionality consists of the assets needed for the application to function, such as the business logic, databases, user authentication, etc.

The separation of application server administration functionality from hosted application functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, network addresses, network ports, or combinations of these methods, as appropriate.'
  desc 'check', 'DR network traffic segmentation is required when using Disaster Recovery Services. Disaster recovery can be used with Asynchronous, NearSync, and Metro Availability replications only if both the primary site and the recovery site are configured with Network Segmentation.

Validate that Disaster Recovery Services is configured to use Specific Network Traffic Segmentation.  

If Disaster Recovery services are not in use this check is NA.

1. Log in to the Prism Elements web console and click the gear icon at the top-right corner of the page.
2. In the left pane, click "Network Configuration".
3. In the details pane, on the Internal Interfaces tab, review the existing interfaces to ensure there is an identified interface for DR traffic.

If no identified network interface is defined for DR traffic, this is a finding.'
  desc 'fix', 'For the most current setup instructions, refer to the version-specific AOC Security Guide on the Nutanix Portal:

https://portal.nutanix.com/page/documents/details?targetId=Nutanix-Security-Guide-v5_20:Nutanix-Security-Guide-v5_20

An excerpt from the AOS Security Guide is provided.

Isolating the traffic associated with a specific service (DR) is a two-step process. 

To isolate a service to a separate virtual network, complete the following:

1. Log in to the Prism web console and click the gear icon at the top-right corner of the page.
2. In the left pane, click "Network Configuration".
3. In the details pane, on the Internal Interfaces tab, click "Create New Interface".
4. On the Interface Details tab, complete the following:
     a. Specify a descriptive name for the network segment.
     b. (On AHV) Optionally, in VLAN ID, specify a VLAN ID.
        Note: Ensure that the VLAN ID is configured on the physical switch.
     c. In Bridge (on AHV) or CVM Port Group (on ESXi), select the bridge or port group created for the network segment.
     d. To specify an IP address pool for the network segment, click "Create New IP Pool", and then, in the IP Pool dialog box, do the following:
        i. In Name, specify a name for the pool.
       ii. In Netmask, specify the network mask for the pool.
      iii. Click "Add an IP Range", specify the start and end IP addresses in the IP Range dialog box that is displayed.
       iv. Use Add an IP Range to add as many IP address ranges as needed.
           Note: Add at least n+1 IP addresses in an IP range considering n is the number of nodes in the cluster.
        v. Click "Save".
       vi. Use Add an IP Pool to add more IP address pools. Use only one IP address pool at any given time.
      vii. Select the IP address pool to be used, and then click "Next".
            Note: An existing unused IP address pool can also be used.
5. On the Feature Selection tab, do the following:
Note: Network segmentation cannot be enabled for multiple services at the same time. Complete the configuration for one service before enabling network segmentation for another service.
     a. Select the service whose traffic is to be isolated.
     b. Configure the settings for the selected service.
       Note: The settings on this page depend on the services selected. For information about service-specific settings, refer to Service-Specific Settings and Configurations.
     c. Click "Save".
6. In the "Create Interface" dialog box, click "Save".
Note: The CVMs are rebooted multiple times, one after another. This procedure might trigger more tasks on the cluster. For example, if configuring network segmentation for disaster recovery, the firewall rules are added on the CVM to allow traffic on the specified ports through the new CVM interface and updated when a new recovery cluster is added or an existing cluster is modified.

What to do next: 
Refer to Service-Specific Settings and Configurations for any additional tasks that are required after the network for a service is segmented.

Disaster Recovery with Protection Domains:
The settings for configuring network segmentation for disaster recovery apply to all Asynchronous, NearSync, and Metro Availability replication schedules. Disaster recovery can be used with Asynchronous, NearSync, and Metro Availability replications only if both the primary site and the recovery site are configured with Network Segmentation. Before enabling or disabling the network segmentation on a host, disable all the disaster recovery replication schedules running on that host.
Note: Network segmentation does not support disaster recovery with Leap.

Remote Site Configuration:
After configuring network segmentation for disaster recovery, configure remote sites at both locations. Reconfigure remote sites if network segmentation is disabled.
For information about configuring remote sites, refer to Site Configuration in the Data Protection and Recovery with Prism Element Guide.

Segmenting a Stretched Layer 2 Network for Disaster Recovery:
A stretched Layer 2 network configuration allows the source and remote metro clusters to be in the same broadcast domain and communicate without a gateway.
About this task:
Network segmentation can be enabled for disaster recovery on a stretched Layer 2 network that does not have a gateway. A stretched Layer 2 network is usually configured across the physically remote clusters such as a metro availability cluster deployment. A stretched Layer 2 network allows the source and remote clusters to be configured in the same broadcast domain without the usual gateway.
Refer to AOS Release Notes for minimum AOS version required to configure a stretched Layer 2 network.
To configure a network segment as a stretched L2 network, do the following.

Procedure:
Run the following command:
nutanix@cvm$ network_segmentation --service_network --service_name=kDR --ip_pool=DR-ip-pool-name --service_vlan=DR-vlan-id --desc_name=Description --host_physical_network=portgroup/bridge --stretched_metro
Replace the following: (Refer to Isolating Service-Specific Traffic for the information)
* DR-ip-pool-name with the name of the IP Pool created for the DR service or any existing unused IP address pool.
* DR-vlan-id with the VLAN ID being used for the DR service.
* Description with a suitable description of this stretched L2 network segment.
* portgroup/bridge with the details of Bridge or CVM Port Group used for the DR service.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57603r846440_chk'
  tag severity: 'medium'
  tag gid: 'V-254118'
  tag rid: 'SV-254118r858375_rule'
  tag stig_id: 'NUTX-AP-000895'
  tag gtitle: 'SRG-APP-000211-AS-000146'
  tag fix_id: 'F-57554r858375_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
