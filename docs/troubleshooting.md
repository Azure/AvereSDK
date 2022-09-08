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

When contacting support, please include the output of any script invocations that are failing.

For help with Microsoft Azure-based systems, open a ticket from the Azure portal:

1. From [https://portal.azure.com](https://portal.azure.com), select **Resource groups**.
1. Browse to the resource group containing the cluster with the issue, and click one of the cluster VMs.
1. Scroll down to the bottom of the left panel to the option **New support request**.
1. Fill out the request form.

   **NOTE:** In the **Service** section on page 1, select **All services** and look under the category **Storage** to find Avere vFXT.
