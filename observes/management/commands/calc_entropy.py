from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand
from django.utils.dateparse import parse_datetime
from django.utils.timezone import now
from django.db.models import Avg, Max, Min, Sum
from django.db import connection

import environ
import json
import requests
import time
import os
import pandas as pd
import numpy as np

from math import log2

from ...models import Hash, Scan, AvclassResult, RawReportEntropies


# BaseCommandを継承して作成
class Command(BaseCommand):
    # python manage.py help count_entryで表示されるメッセージ
    help = 'get a report of registered hashes from VT'
    def get_max_detection(self, ex_rep):
        fam = np.nan
        file = np.nan
        beh = np.nan
        clas = np.nan
        unk = np.nan
        for k, v in ex_rep.items():
            #         print(k)
            dets = [v2["name"] for v2 in v]
            temp = [len(dets["av"]) for dets in v]
            max_det = dets[temp.index(max(temp))]
            if k == "FILE":
                file = max_det
            elif k == "FAM":
                fam = max_det
            elif k == "BEH":
                beh = max_det
            elif k == "CLASS":
                clas = max_det
            elif k == "UNK":
                unk = max_det
    #     print([fam, file, beh, clas, unk])
        return np.array([fam, file, beh, clas, unk])

    def agg_max_votes(self, x):
        try:
            return x.value_counts().index[0]
        except:
            return 'failed'

    def map_engine_detecion(self, engine, report):
        if report:
            if engine in json.loads(report)['scans'].keys():
                return json.loads(report)['scans'][engine]['result']
        return 'nan'

    def calc_entropy(self, series):
        e = 0
        for v in series.values:
            e += -1 * v * log2(v)
        return e

    def handle(self, *args, **kwargs):
        df_scan = pd.read_sql_query('SELECT * FROM observes_scan', connection)
        df_avc = pd.read_sql_query('SELECT * FROM observes_avclassresult', connection)

        df = pd.merge(df_scan, df_avc, left_on='id', right_on='scan_id')
        df.dropna(inplace=True)
        df = df.loc[:, ~df.columns.duplicated()]
        df["scan_date"] = pd.to_datetime(df["scan_date"])

        df["family"] = np.nan
        df["file"] = np.nan
        df["beh"] = np.nan
        df["class"] = np.nan
        df["unk"] = np.nan

        df["vote"] = df["result"].apply(
            lambda x: self.get_max_detection(json.loads(x)))
        
        df[["family", "file", "beh", "class", "unk"]] = df["vote"].to_list()
        unks = df.unk[(df.unk != 'nan') & (df.unk)].unique().tolist()
        df.loc[(df.unk.isin(unks)) & (df.family.isna()), "family"] = df.loc[(
            df.unk.isin(unks)) & (df.family.isna()), "unk"]
        df.dropna(inplace=True)
        malwrs = df.groupby("sha256_id_x")[
            ["sha256_id_x", "family", "file", "beh", "class", "unk"]].agg(lambda x: self.agg_max_votes(x))
        df["from_first_scan"] = df.groupby(["sha256_id_x"])["scan_date"].apply(
            lambda x: (x - x.min()) // np.timedelta64(1, 'm'))
        
        available_engines = set([])

        for idx, row in df.iterrows():
            rep = row['report']
            engines = list(json.loads(rep)['scans'].keys())
            available_engines = available_engines | set(engines)
        
        available_engines = list(available_engines)
        df_token = df_scan.copy()

        for e in available_engines:
            df_token[e] = df_token.report.map(lambda x: self.map_engine_detecion(e, x))
        
        df_token = pd.merge(df_token, malwrs[[
                            'family', 'file', 'beh', 'class', 'unk']], left_on='sha256_id', right_on='sha256_id_x', how='inner')
        
        ent_eng = []
        ent_det = []
        ent = []
        vcs = []

        for e in available_engines:
            for d in df_token[(df_token.family != 'nan')][e].unique():
                #     for d in df_token[e].unique():
                if d == 'nan' or not d:
                    continue
                vc = df_token[(df_token.family != 'nan') & (
                    df_token[e] == d)]['family'].value_counts(normalize=True)
                entropy = self.calc_entropy(vc)
                RawReportEntropies.objects.update_or_create(
                    engine = e,
                    report = d,
                    defaults = {
                        "entropy": float(entropy),
                        "valuecounts": vc.to_json()
                    }
                )
"""
select sha256, family 
 from AvclassResults
 group by sha256, family
 having count(*) >=
  all(select count(*)
       from AvclassResults B
       where A.sha256 = B.sha256
       group by family
     ) as C
 order by sha256, family
"""
