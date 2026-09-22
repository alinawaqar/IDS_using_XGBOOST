Set-Location "C:\ids_dashboard_package - Copy"

docker compose up -d

$env:IDS_INTERNAL_KEY = (docker compose exec -T backend printenv IDS_INTERNAL_KEY).Trim()

$env:INTERFACE_INDEX = "5"

python .\utils\live_ids.py