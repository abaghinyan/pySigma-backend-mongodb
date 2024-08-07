import pytest
from sigma.backends.mongodb import MongoDBBackend
from sigma.collection import SigmaCollection


@pytest.fixture
def mongodb_backend():
    return MongoDBBackend()


@pytest.fixture
def mongodb_custom_backend():
    return MongoDBBackend(
        query_settings=lambda x: {"custom.query.key": x.title},
        output_settings={"custom.key": "customvalue"},
    )


def test_mongodb_and_expression(mongodb_backend: MongoDBBackend):
    rule = SigmaCollection.from_yaml(
        """
title: Potential DCOM InternetExplorer.Application DLL Hijack - Image Load
status: test
description: Detects potential DLL hijack of "iertutil.dll" found in the DCOM InternetExplorer.Application Class
references:
    - https://threathunterplaybook.com/hunts/windows/201009-RemoteDCOMIErtUtilDLLHijack/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR), wagga
date: 2020/10/12
modified: 2022/12/18
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.t1021.003
logsource:
    product: windows
    category: image_load
detection:
    selection:
        data.Event.EventData.Image|endswith: 'iexplore.exe'
        data.Event.EventData.ImageLoaded|endswith: 'iertutil.dll'
    condition: selection
falsepositives:
    - Unknown
level: critical
        """
    )
    print(mongodb_backend.convert(rule))
    assert mongodb_backend.convert(rule) == ['{ "$and": [ { "data.Event.EventData.Image": { "$regex": "iexplore\\\\.exe$" } }, { "data.Event.EventData.ImageLoaded": { "$regex": "iertutil\\\\.dll$" } } ] }']

