import csv, matplotlib, matplotlib.ticker
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import Rectangle
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':9,'axes.edgecolor':'#52514e'})
INK,INK2,SURF='#0b0b0b','#52514e','#fcfcfb'
SEQ=['#cde2fb','#9ec5f4','#6da7ec','#3987e5','#256abf','#184f95','#0d366b']
cmap=LinearSegmentedColormap.from_list('seq',SEQ)
rows=list(csv.DictReader(open('sorties/v19.2/2_detail_techniques.csv',encoding='utf-8-sig'),delimiter=';'))
order=["T1595","T1566","T1539","T1078","T1078.004","T1133","T1087","T1018","T1518.001","T1548",
       "T1059.008","T1005","T1602.002","T1048","T1567","T1565","T1070","T1486"]
names={r['technique']:r['nom'] for r in rows}
sos=["SO1","SO2","SO3","SO4","SO5","SO6"]
val={(r['scenario'],r['technique']):int(r['nb_groupes']) for r in rows}
vmax=max(val.values())
fig,ax=plt.subplots(figsize=(11,4.2),dpi=200); fig.patch.set_facecolor('white')
for i,so in enumerate(sos):
    for j,t in enumerate(order):
        x,y=j,len(sos)-1-i
        if (so,t) not in val:
            continue
        v=val[(so,t)]
        if v==0:
            ax.add_patch(Rectangle((x+0.04,y+0.04),0.92,0.92,facecolor='white',edgecolor='#c1121f',lw=1.6,hatch='////'))
            ax.text(x+0.5,y+0.5,'0',ha='center',va='center',color='#c1121f',fontsize=9,fontweight='bold',bbox=dict(boxstyle='round,pad=0.15',fc='white',ec='none'))
        else:
            c=cmap((v-1)/(vmax-1) if vmax>1 else 1)
            ax.add_patch(Rectangle((x+0.04,y+0.04),0.92,0.92,facecolor=c,edgecolor='white',lw=1))
            ax.text(x+0.5,y+0.5,str(v),ha='center',va='center',color='white' if v>=5 else INK,fontsize=9)
ax.set_xlim(0,len(order)); ax.set_ylim(0,len(sos))
ax.set_xticks([j+0.5 for j in range(len(order))])
ax.set_xticklabels([f"{t}\n{names.get(t,'')}" for t in order],rotation=60,ha='right',fontsize=7,color=INK2)
ax.set_yticks([i+0.5 for i in range(len(sos))]); ax.set_yticklabels(list(reversed(sos)),color=INK)
for s in ax.spines.values(): s.set_visible(False)
ax.tick_params(length=0)
sm=plt.cm.ScalarMappable(cmap=cmap,norm=plt.Normalize(1,vmax)); cb=fig.colorbar(sm,ax=ax,fraction=0.025,pad=0.01)
cb.set_label('Nombre de groupes télécom\n(sur 22) utilisant la technique',color=INK2,fontsize=8); cb.outline.set_visible(False)
ax.add_patch(Rectangle((0,0),0,0))
leg=ax.legend(handles=[Rectangle((0,0),1,1,facecolor='white',edgecolor='#c1121f',hatch='////',lw=1.4)],
              labels=['Technique non observée chez les groupes télécom'],loc='upper left',bbox_to_anchor=(0,1.13),frameon=False,fontsize=8)
ax.set_title('Techniques des scénarios opérationnels observées chez les groupes ciblant les télécoms (ATT&CK v19.2)',loc='left',fontsize=10,color=INK,pad=26)
plt.tight_layout(); plt.savefig('sorties/figure_heatmap_scenarios.png',bbox_inches='tight',facecolor='white')

# Figure 2 : angles morts
am=list(csv.DictReader(open('sorties/v19.2/3_angles_morts.csv',encoding='utf-8-sig'),delimiter=';'))
PERIM={'T1190','T1003','T1021','T1136','T1505','T1016','T1555','T1090','T1685'}
am=am[:18]
fig,ax=plt.subplots(figsize=(8,5.2),dpi=200)
ys=list(range(len(am)))[::-1]
for y,r in zip(ys,am):
    rel=r['technique'] in PERIM
    ax.barh(y,int(r['nb_groupes']),height=0.7,color='#2a78d6' if rel else '#c9c8c2')
    ax.text(int(r['nb_groupes'])+0.2,y,r['nb_groupes'],va='center',fontsize=8,color=INK2)
ax.set_yticks(ys); ax.set_yticklabels([f"{r['technique']} {r['nom']}" for r in am],fontsize=8,color=INK)
ax.set_xlabel('Nombre de groupes télécom (sur 22)',color=INK2,fontsize=8)
for s in ['top','right','left']: ax.spines[s].set_visible(False)
ax.tick_params(axis='y',length=0); ax.grid(axis='x',color='#e6e5e0',lw=0.6); ax.set_axisbelow(True)
from matplotlib.patches import Patch
ax.legend(handles=[Patch(color='#2a78d6'),Patch(color='#c9c8c2')],labels=['Pertinente pour le périmètre NMS / accès d\'administration','Générique (poste de travail, préparation de l\'attaque)'],
          loc='upper left',bbox_to_anchor=(0,-0.1),ncol=1,frameon=False,fontsize=8)
ax.xaxis.set_major_locator(matplotlib.ticker.MultipleLocator(2))
ax.set_title('Angles morts : techniques fréquentes chez les groupes télécom,\nabsentes des six scénarios opérationnels',loc='left',fontsize=10,color=INK)
plt.tight_layout(); plt.savefig('sorties/figure_angles_morts.png',bbox_inches='tight',facecolor='white')
print('ok')
