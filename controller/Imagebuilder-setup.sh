# Setup resources to be able to make a new image and store it in a shared 
# image gallery that can be used to populate a new vfxt controller version
# in marketplace.

# Environment Variables
subscriptionID=<subid>  # Avere FreeBSD Build Environment Subscription
location=<location>
additionalregion=<additionallocation>
sigResourceGroup=<rgname>
identityName=<identityname>
sigName=<signame>
imageDefName=<imagedefname>
runOutputName=<runoutputname>


# Not all of these steps need to be run if the 
# Shared Image Gallery already exists.


# Create Resource Group
az group create -n $sigResourceGroup -l $location --subscription $subscriptionID 

# Create Managed Identity for azure image builder
az identity create -g $sigResourceGroup -n $identityName --subscription $subscriptionID
imgBuilderCliId=$(az identity show -g $sigResourceGroup -n $identityName --subscription $subscriptionID --query clientId -o tsv)
imgBuilderId=/subscriptions/$subscriptionID/resourcegroups/$sigResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$identityName

# Add role assignment.  On the microsoft tenant, this doesn't work from 
# unmanaged hosts. you might have to do this in the azure portal.
az role assignment create \
    --assignee $imgBuilderCliId \
    --role "<role>" \    # See azure image builder for appropriate role to use here.
    --scope /subscriptions/$subscriptionID/resourceGroups/$sigResourceGroup

# Create Shared Image Gallery
az sig create \
    -g $sigResourceGroup --subscription $subscriptionID \
    --gallery-name $sigName


# Create Image Definition
az sig image-definition create \
   -g $sigResourceGroup --subscription $subscriptionID\
   --gallery-name $sigName \
   --gallery-image-definition $imageDefName \
   --publisher Microsoft \
   --offer vfxt-controller \
   --sku 20_04-lts-gen2 \
   --os-type Linux \
   --hyper-v-generation V2 \
   --features SecurityType=TrustedLaunchSupported

# Get image template and customize it.  
# The sleeps were needed to help the sed commands finish writing the file.
curl https://raw.githubusercontent.com/Azure/azvmimagebuilder/master/quickquickstarts/1_Creating_a_Custom_Linux_Shared_Image_Gallery_Image/helloImageTemplateforSIG.json -o helloImageTemplateforSIG.json
sed -i -e "s/<subscriptionID>/$subscriptionID/g" helloImageTemplateforSIG.json
sleep 2
sed -i -e "s/<rgName>/$sigResourceGroup/g" helloImageTemplateforSIG.json && \
sleep 2
sed -i -e "s/<imageDefName>/$imageDefName/g" helloImageTemplateforSIG.json && \
sleep 2
sed -i -e "s/<sharedImageGalName>/$sigName/g" helloImageTemplateforSIG.json && \
sleep 2
sed -i -e "s/<region1>/$location/g" helloImageTemplateforSIG.json && \
sleep 2
sed -i -e "s/<region2>/$additionalregion/g" helloImageTemplateforSIG.json && \
sleep 2
sed -i -e "s/<runOutputName>/$runOutputName/g" helloImageTemplateforSIG.json && \
sleep 2
sed -i -e "s%<imgBuilderId>%$imgBuilderId%g" helloImageTemplateforSIG.json
sleep 2
sed -i '/"customize": \[/,/\],/c\
        "customize": [\
            {\
                "type": "Shell",\
                "name": "InstallVfxtPy",\
                "scriptUri": "https://raw.githubusercontent.com/Azure/AvereSDK/main/controller/install.sh"\
            }\
        ],' helloImageTemplateforSIG.json


# Create Image Template
# A Image template will need to be recreated if the InstallVfxtPy script
# contents are updated.  If you're just wanting to pull new ubuntu updates 
# you can just run the image template again.

current_date_time=$(date +"%Y%m%d-%H%M%S")
templatename="vfxt-controller-image-template-$current_date_time"

az resource create \
    --resource-group $sigResourceGroup \
    --properties @helloImageTemplateforSIG.json \
    --is-full-object \
    --resource-type Microsoft.VirtualMachineImages/imageTemplates \
    -n $templatename \
    --subscription $subscriptionID

# Run Image Template
az resource invoke-action \
     --resource-group $sigResourceGroup \
     --resource-type  Microsoft.VirtualMachineImages/imageTemplates \
     -n $templatename \
     --action Run \
     --subscription $subscriptionID

# Helpful command to remove a template
az resource delete \
    --resource-group $sigResourceGroup \
    -n helloImageTemplateforSIG01 \
    --resource-type Microsoft.VirtualMachineImages/imageTemplates \
    --subscription $subscriptionID