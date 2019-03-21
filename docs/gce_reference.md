# Quick Reference – Using vfxt.py with Google Cloud Platform

This section gives an overview of how to configure a vfxt.py installation to be able to create Avere clusters in a Google Compute Engine  environment. (Note that vfxt.py terms use GCE to indicate Google services and not "GCP", which is a reference to the full Google Cloud Platform product family.)

>Note: Read the [vFXT Installation Guide for Google Cloud Platform](<https://azure.github.io/Avere/#vfxt>) for complete information about the configuration required to create vFXT clusters in the Amazon cloud computing environment. 

Configuring the GCE environment to allow vfxt.py access includes the following steps: 

* Check your project's resource quotas and request an increase if needed. (Note that quota increase requests might take a day or more to be fulfilled.)
* Create a Google Compute instance  
* Send project information to Avere Systems to gain access to the vFXT image
* Configure a Service Account:

  * If using a remote console to access the GCE system, export the default service account credential as a JSON key file for authenticating the remote console to the GCE instance. 

  Optionally, you can create and use a new service account instead of using the default account. The steps are the same - export the credential as a JSON key file.  

  * If using a GCE cloud instance to run vfxt.py on the GCE system, you will obtain an on-instance authentication token instead of using a JSON key. This token will use the service account credentials the instance was created with (either the default service account or a separate account that you created for creating the cloud instance). 

* Install the Google API Python client library to allow Python to interact with the GCE API. 

## Install the Google API Library 

On the system where you will run vfxt.py, install the Google API Python Client Library. 

`    pip install –-upgrade --user google-api-python-client`

## GCE authentication options

When issuing a vfxt.py command on a Google Cloud system, you must include the appropriate parameters to authenticate the system running vfxt.py to your Google Cloud Project.

Some steps are necessary ahead of time. If running vfxt.py from a remote console, you must download a key file associated with a service account. If running fvxt.py from a cloud console, you must make sure the instance used has full API privileges. 

### Cloud Instance

If using a GCE instance to run vfxt.py, create an instance that has full access to all cloud APIs. This enables API-based read and write access for compute and storage resources. 

To authorize the instance, vfxt.py can query the instance metadata to obtain an authentication token. Pass the `--on-instance` value to indicate that vfxt.py should obtain a token locally. 

`vfxt.py --cloud-type gce --on-instance`

Note that Google Cloud Shell cannot be used to run vfxt.py, since it runs in a temporary container and does not have the required IP connectivity to the cloud project.  

### Remote Console 

If using a remote system to run vfxt.py, you must obtain and supply a JSON key file from the GCE service account. Follow the key management instructions in the [Google Cloud Service Accounts documentation](<https://cloud.google.com/iam/docs/creating-managing-service-account-keys>) to learn how to download the JSON key file from the service account. 

Use the `--key-file` option to provide the file to authenticate the remote system. 

`vfxt.py --cloud-type gce --key-file` *key_file*`.json`

**Note:** Older Google service accounts provided .p12 PKCS#12 files instead of JSON key files. If your service account uses .p12, also use the `--client-email` option to specify the service account email associated with the key.

If you have configured the gcloud utility with your credentials, you can use the `--from-environment` option to import them into vfxt.py. 

   * **Note:** You must issue the command `gcloud auth application-default login` to authorize the local application to use your user credentials for API access before invoking vfxt.py. 

    `vfxt.py --cloud-type gce --from-environment`

**Note:** Use gcloud auth application-default login to configure credentials before invoking vfxt.py. 

## GCE Environment Options

For each vfxt.py command, you must pass environment options that describe your cloud project network configuration.  

The network and zone options are required for all actions. These values describe where in your cloud space the vFXT clusters are (or will be created). For cross-zone configurations, you can provide multiple zones in a space-separated list. 

Optionally, use the `--subnetwork` option to specify a subnet. 

```
vfxt.py	--cloud-type gce 
	--key-file key_file.json 
	--network network 
	--zone zone zone2 zone3 
	--subnetwork subnetwork 
```

## Additional GCE Configuration Options

Refer to the list of commands in GCE Options or `vfxt.py --help` for details about other Google-specific parameters. 

Extra GCE-specific options include:

* Instance tagging 
* Instance metadata
* Local SSD disks
* Additional environment options

## GCE Cluster Settings 

This table shows example values that can be used when creating a vFXT cluster on Google Cloud. Please work with your Technology Solutions or support representative to determine the best options.

|   | vfxt.py script option | Default value | Other value options |
| ---------- | ---------- | ------------------ | ---------- | 
| VM instance type | `--instance-type` | n1-highmem-8 | n1-highmem-32 |
| SSD type | `--data-disk-type` | pd-ssd (persistent) | local-ssd |
| Node cache size | `--node-cache-size` | `1000` (for persistent disks) <br/>`750` (for local disks, in multiples of 375) | persistent disks: `4000` (min `250`, max `8000`; low numbers are intended for test configurations) <br/>local disks: `1500` (max `3000`)  |
|Number of nodes | `--nodes` | `3` | Up to `20` |
| Bucket creation | `--no-corefiler` | Omit this option | `--no-corefiler` |
