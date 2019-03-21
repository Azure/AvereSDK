# Troubleshooting

If you have trouble using the vfxt.py script, check the following settings and messages before contacting support. 

## Common Issues

Common errors include the following situations: 
* Insufficient cloud quotas
* Faulty permissions/role configuration
* Misconfigured network settings that do not allow access to cloud API endpoints

## Debugging Help

The `--debug` option can be added to any vfxt.py command. It gives verbose feedback that can help you to identify useful status messages or detect problems in backend interaction that come about during the script's execution. 

You also can use the `--log` option to direct the standard error and output streams to a log file: 

    vfxt.py --log logfilename.txt --debug <main vfxt.py commands and options> 

Save the debugging output from any unresolved situations to send along with your support request. 

## Contacting Support 

There are two different methods for getting help with your vFXT cluster. For Azure clusters you should use the ticket system built in to the cloud portal; for AWS and GCE clusters you should contact Microsoft Customer Service and Support (formerly Avere Global Services) online or by phone.

When contacting support, please include the output of any script invocations that are failing.

### Azure users

For help with Microsoft Azure-based systems, open a ticket from the Azure portal: 

1. From https://portal.azure.com, select **Resource groups**.
1. Browse to the resource group containing the cluster with the issue, and click one of the cluster VMs. 
1. Scroll down to the bottom of the left panel to the option **New support request**.
1. Fill out the request form. 

   **Note:** In the **Service** section on page 1, select **All services** and look under the category **Storage** to find Avere vFXT.

### AWS and GCE users 

For vFXT clusters using Amazon Web Services or Google, open a ticket by contacting Avere support. 

There are several ways to reach Avere support:

* **Telephone** 
  * US and Canada - toll free: 1-888-88-AVERE (888-882-8373), press 2 for support
  * United Kingdom: +44 20 3695 1638, press 2 for support
  * US or International: +1-412-894-2570, press 2 for support

* **Web** - Use the links under Support Information on [https://www.microsoft.com/avere/contact-us](https://www.microsoft.com/avere/contact-us)   
 
* **Email** - averesupport@microsoft.com
