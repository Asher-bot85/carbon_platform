Phase 1 — Create the Kubernetes Cluster

Where: Terminal 1 (any directory)

Creates a local Kubernetes cluster running inside Docker.

bash
kind create cluster --name ecocapture-cluster

Verify the cluster is up and ready:

bash
kubectl cluster-info --context kind-ecocapture-cluster
kubectl get nodes

You should see one node with status Ready.

Phase 2 — Build the Docker Image

Where: Terminal 1, inside the project folder

Move into your project directory:

bash
cd ~/carbon_platform1

Build the application image from the Dockerfile:

bash
docker build -t ecocapture-os:latest .

Confirm the image was built successfully:

bash
docker images | grep ecocapture-os

Phase 3 — Load Images into kind

kind cannot see your host machine's Docker images automatically — each image must be explicitly loaded into the cluster.

Where: Terminal 1

Load your application image:

kind load docker-image ecocapture-os:latest --name ecocapture-cluster

## Pull and load the Suricata image (used by the attack simulation's sidecar container):

docker pull jasonish/suricata:latest
kind load docker-image jasonish/suricata:latest --name ecocapture-cluster

## Verify both images are present inside the cluster node:

docker exec ecocapture-cluster-control-plane crictl images | grep -E "ecocapture-os|suricata"

## Phase 4 — Deploy the Application

Where: Terminal 1, inside the project folder

Apply the full Kubernetes manifest (namespace, ConfigMaps, Secret, PVC, Deployment, Job, Service, NetworkPolicy):

kubectl apply -f carbon-platform-k8s.yaml

## Immediately delete the attack Job so it doesn't fire before you're ready to demo it:

kubectl delete job ecocapture-attack-sim -n ecocapture-os --ignore-not-found

## Watch the dashboard pods start up:

kubectl get pods -n ecocapture-os -w

Wait until both ecocapture-os-dashboard-xxxxx pods show 1/1 and Running. Then press Ctrl+C to stop watching.

If a pod fails to start, debug with:

kubectl describe pod -n ecocapture-os -l app=ecocapture-os,component=dashboard
kubectl logs -n ecocapture-os -l app=ecocapture-os,component=dashboard

## Phase 5 — Access the Streamlit Dashboard

Where: Terminal 1 — leave this command running, do not close this terminal

bash
kubectl port-forward -n ecocapture-os svc/ecocapture-os-service 8501:80

Where to view it: open your browser to

http://localhost:8501

Confirm all four tabs load correctly:

🏭 Carbon Capture Operations
📊 ESG Climate Report Auditor
🔐 DevSecOps Pipeline Manifest Scanner
🤖 AI Anomaly Detection Training

In the sidebar, you can optionally tick "Enable Live Monitoring Mode (auto-refresh)" so the dashboard updates itself every few seconds without manual clicks.

### Phase 6 — Install ArgoCD

Where: Terminal 2 (open a new terminal — leave Terminal 1's port-forward running)

Create a dedicated namespace for ArgoCD:

bash
kubectl create namespace argocd

## Install ArgoCD's official components:

kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

## Wait for all ArgoCD pods to become ready (this can take 1-3 minutes):

bash
kubectl get pods -n argocd -w

Wait until everything shows Running, then Ctrl+C.

### Phase 7 — Access the ArgoCD UI

Where: Terminal 3 (open a third terminal — Terminal 1 and Terminal 2 stay as they are)

bash
kubectl port-forward svc/argocd-server -n argocd 8080:443

Where to view it: open a new browser tab to

https://localhost:8080

Your browser will warn about a self-signed certificate — click Advanced → Proceed anyway (this is expected for a local lab cluster).

Get the admin login password — back in Terminal 2:

kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

This prints a password to the screen. Copy it.

Log in to the ArgoCD UI:

Username: admin
Password: (the value you just copied)

### Phase 8 — Create the ArgoCD Application

This tells ArgoCD which Git repository to watch and which cluster/namespace to deploy it to.

Where: Terminal 2, inside the project folder

kubectl apply -f argocd-application.yaml

## Phase 9 — Verify ArgoCD Is Managing the App

Where: Browser tab with https://localhost:8080 (from Phase 7)

Click on the ecocapture-os application tile. You should see a visual graph of every resource ArgoCD is managing (Deployment, Service, PVC, ConfigMaps, Job), each showing status Synced and Healthy.

Where: Terminal 2

kubectl get pods -n ecocapture-os

Your dashboard pods should still be running — ArgoCD has now taken over management of this namespace.

#### Phase 10 — Run the Attack Simulation

Where: Terminal 2

Delete any previous run of the attack Job, then reapply the manifest to trigger a fresh run:

kubectl delete job ecocapture-attack-sim -n ecocapture-os --ignore-not-found
kubectl apply -f carbon-platform-k8s.yaml

Watch the attacker's live output:

kubectl logs -n ecocapture-os job/ecocapture-attack-sim -c attacker -f

### Phase 11 — Confirm Alerts in the Dashboard

Where: Browser tab with http://localhost:8501 (still open from Phase 5)

Click "🔄 Refresh Simulated Telemetry" in the sidebar (or wait ~3 seconds if Live Monitoring Mode is enabled).

You should now see:

The sidebar CRITICAL counter increase
Tab 1 → "Real-Time Intrusion Monitoring Timeline" filling with red CRITICAL entries
Entries tagged [Suricata-OT] confirming the network-layer IDS sidecar is working
The "Global Security Audit Trail" expander at the bottom of the page showing the full history

########## Demonstrating GitOps Live (Optional Demo)

This shows that ArgoCD automatically applies changes pushed to Git — no manual kubectl apply required.

Where: Terminal 2, inside the project folder

bash
nano carbon-platform-k8s.yaml

Use Ctrl+W inside nano, search for replicas: 2, and change it to replicas: 1. Save: Ctrl+O, Enter, Ctrl+X.

bash
git add carbon-platform-k8s.yaml
git commit -m "Scale down dashboard replicas"
git push

Switch to the ArgoCD browser tab (https://localhost:8080). Within about 3 minutes, ArgoCD detects the Git change and automatically syncs the cluster. To force it instantly instead of waiting, click the "SYNC" button on the ecocapture-os application tile.

Verify the change was applied:

bash
kubectl get pods -n ecocapture-os -l app=ecocapture-os,component=dashboard

You should now see only 1 dashboard pod running instead of 2.

######### Full Cleanup (When You're Done)

Where: Terminal 2

bash
kubectl delete -f argocd-application.yaml
kubectl delete namespace argocd
kubectl delete -f carbon-platform-k8s.yaml
kind delete cluster --name ecocapture-cluster

Optionally remove the Docker images too:

bash
docker rmi ecocapture-os:latest
docker rmi jasonish/suricata:latest
