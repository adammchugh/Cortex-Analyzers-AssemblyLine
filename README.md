[![euler](cortex.png)](https://github.com/TheHive-Project/Cortex)

## template

[![build](https://drone.virtware.top/api/badges/ghislain-bernard/cortex-analyzer-template/status.svg?branch=master)](https://drone.virtware.top "master") [![build](https://drone.virtware.top/api/badges/ghislain-bernard/cortex-analyzer-template/status.svg?branch=develop)](https://drone.virtware.top "develop")

### usage

```console
$ pip install --user cortexutils==2.0.0
Collecting cortexutils==2.0.0
  Downloading cortexutils-2.0.0-py2.py3-none-any.whl (20 kB)
Installing collected packages: cortexutils
Successfully installed cortexutils-2.0.0

$ cat job/input/input.json | jq
{
  "config": {
    "check_pap": true,
    "check_tlp": true,
    "delay": 10,
    "max_pap": 2,
    "max_tlp": 2
  },
  "data": "8.8.8.8",
  "dataType": "ip",
  "pap": 1,
  "tlp:": 1
}

$ template/template.py job

$ cat job/output/output.json | jq
{
  "success": true,
  "summary": {
    "taxonomies": [
      {
        "level": "info",
        "namespace": "template",
        "predicate": "ip",
        "value": "8.8.8.8"
      }
    ]
  },
  "artifacts": [
    {
      "tags": [
        "template"
      ],
      "tlp": 2,
      "dataType": "ip",
      "data": "8.8.8.8"
    }
  ],
  "full": {
    "data": "8.8.8.8",
    "input": {
      "config": {
        "check_pap": true,
        "check_tlp": true,
        "delay": 0,
        "max_pap": 2,
        "max_tlp": 2
      },
      "data": "8.8.8.8",
      "dataType": "ip",
      "pap": 1,
      "tlp:": 1
    }
  }
}
```
