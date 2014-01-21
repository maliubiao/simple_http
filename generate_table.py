import simple_table 
import json

SD, DS = simple_table.generate()
simple_table.test(SD, DS)

f = open("SD.key", "w") 
f.write(json.dumps(SD))
f.close()

f = open("DS.key", "w")
f.write(json.dumps(DS))
f.close()
