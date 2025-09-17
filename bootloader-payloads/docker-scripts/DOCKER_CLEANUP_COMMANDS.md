# Docker Cleanup Commands

## Quick Cleanup Script
Run the automated cleanup script:
```bash
./cleanup_docker.sh
```

## Manual Cleanup Commands

### 1. List Current Containers and Images
```bash
# List all containers (running and stopped)
docker ps -a

# List all images
docker images

# List only SiemensS7-Bootloader related images
docker images | grep siemens
```

### 2. Remove Specific Images
```bash
# Remove the payload image
docker rmi siemens-s7-payloads-enhanced

# Force remove image (even if containers are using it)
docker rmi -f siemens-s7-payloads-enhanced
```

### 4. Nuclear Option - Clean Everything
```bash
# Remove all stopped containers
docker container prune -f

# Remove all unused images
docker image prune -a -f

# Remove all unused volumes
docker volume prune -f

# Remove all unused networks
docker network prune -f

# Remove everything unused (containers, images, networks, volumes, build cache)
docker system prune -a -f --volumes
```

### 5. Selective Cleanup
```bash
# Remove only dangling images (untagged)
docker image prune -f

# Remove build cache
docker builder prune -f

# Remove containers that exited more than 24 hours ago
docker container prune --filter "until=24h" -f
```

### 6. Check Disk Usage
```bash
# See Docker disk usage
docker system df

# Detailed breakdown
docker system df -v
```

## Testing from Scratch Workflow

1. **Clean up:**
   ```bash
   ./cleanup_docker.sh
   ```

2. **Verify cleanup:**
   ```bash
   docker images | grep siemens
   docker ps -a | grep siemens
   ```

3. **Test fresh build:**
   ```bash
   ./extract_payloads.sh
   ```

4. **Clean up compiled payloads (optional):**
   ```bash
   rm -rf compiled_payloads/
   ```

## Troubleshooting

### If containers won't stop:
```bash
# Kill all containers forcefully
docker kill $(docker ps -q)

# Remove all containers forcefully
docker rm -f $(docker ps -aq)
```

### If images won't delete:
```bash
# Remove all containers first, then images
docker rm -f $(docker ps -aq)
docker rmi -f $(docker images -q)
```

### Check what's using an image:
```bash
# See which containers are using an image
docker ps -a --filter ancestor=siemens-s7-payloads
```