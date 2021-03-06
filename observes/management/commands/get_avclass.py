import json
import os
from django.core.management.base import BaseCommand
from .avclass.avclass2.lib.avclass2_common import AvLabels
from ...models import Hash, Scan, AvclassResult



class Command(BaseCommand):
    default_tag_file = os.path.dirname(__file__)+"/avclass/avclass2/data/tagging"
    default_exp_file = os.path.dirname(__file__)+"/avclass/avclass2/data/expansion"
    default_tax_file = os.path.dirname(__file__)+"/avclass/avclass2/data/taxonomy"

    def handle(self, *args, **kwargs):
        hashes = Hash.objects.all()
        for sha256 in hashes:
            scans = sha256.detection_of_hash.all()
            for scan in scans:
                if scan.avclass_result_of_scan.all():
                    continue
                if not scan.report:
                    continue
                avc = self.get_taxonomy_from_vt_report(scan.report)
                cat_map = {'FAM': [], 'CLASS': [],
                           'BEH': [], 'FILE': [], 'UNK':[]
                          }
                avs = []
                for cat in avc.keys():
                    names = avc[cat]
                    for n in names:
                        avs += n["av"]
                    cat_map[cat]=list(set(avs))
                file = 'nan'
                fam = 'nan'
                beh = 'nan'
                clas = 'nan'
                unk = 'nan'
                for k, v in avc.items():
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

                acr = AvclassResult(sha256=sha256, scan=scan, 
                                    family_count = len(cat_map["FAM"]),
                                    family = fam,
                                    variety_count = len(cat_map["CLASS"]),
                                    variety = clas,
                                    beh_count = len(cat_map["BEH"]),
                                    beh = beh,
                                    file_count = len(cat_map["FILE"]),
                                    file=file,
                                    unk_count=len(cat_map["UNK"]),
                                    unk = unk,
                                    result=avc
                                    )
                acr.save()


    def get_taxonomy_from_vt_report(self, vt):
        av_labels = AvLabels(self.default_tag_file, self.default_exp_file, self.default_tax_file)

        raw_info = av_labels.get_sample_info_vt_v2(vt)
        sample_tags = av_labels.get_sample_tags(raw_info)
        tags = av_labels.rank_tags_with_av(sample_tags)

        avc = {}
        for tag in tags:
            tax =  av_labels.taxonomy.get_info(tag[0])
            if tax[1] not in avc.keys():
                avc[tax[1]]=[]
            avc[tax[1]].append(
                {
                    "name":tax[0].split(":")[-1],
                    "av":tag[1]
                }
            )
        
        return avc


    # tax = av_labels.taxonomy.get_info(rank_tags[0][0])
    # print(tax)
