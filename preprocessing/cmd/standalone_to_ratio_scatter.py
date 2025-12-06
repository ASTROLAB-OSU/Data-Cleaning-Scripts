import json
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

def visualize_occurrence_relationships(json_file, output_path):
    # Load JSON data
    with open(json_file, 'r') as f:
        all_stats = json.load(f)

    # Create figure
    plt.figure(figsize=(15, 10))

    """
    Create threshhold line

    ADJUST THIS FOR CUSTOM CUTOFF LINE

    """
    x_threshold = np.linspace(3000, 200000, 1000)
    y_threshold = []
    for x in x_threshold:
        if x >= 3000 and x <= 5000:
            y_threshold.append(1)
        elif x > 5000 and x <= 20000:
            y_threshold.append((x / 500) - 10)
        elif x > 20000:
            y_threshold.append((x / 50) - 700)
        else:
            y_threshold.append(0)
    
    # Plot threshold curve
    plt.plot(x_threshold, y_threshold, 'r--', label='Threshold Line', linewidth=2)

    # Colors and markers for different datasets
    colors = ['b', 'g', 'r', 'c', 'm', 'y', 'k']
    markers = ['o', 's', '^', 'v', 'D', 'p', '*']

    # Process each dataset
    for idx, (dataset_name, stats) in enumerate(all_stats.items()):
        # Extract data
        standalone = [stat['standalone_count'] for stat in stats]
        followup = [stat['following_count'] for stat in stats]
        prefixes = [stat['prefix'] for stat in stats]

        # Compute ratios (handling cases where followup is zero)
        ratios = []
        for stand, foll in zip(standalone, followup):
            if foll == 0:
                # Use a small value instead of infinity for log scale
                ratios.append(stand)
            else:
                ratios.append(stand / foll)

        # Create scatter plot
        color_idx = idx % len(colors)
        marker_idx = idx % len(markers)
        plt.scatter(standalone, followup,
                   c=colors[color_idx],
                   marker=markers[marker_idx],
                   label=dataset_name,
                   alpha=0.6)

        # Add annotations for notable points
        for i, prefix in enumerate(prefixes):
            # Adjust threshold for annotation in log space
            if (np.log10(standalone[i]) > np.log10(max(standalone)) - 1 or
                np.log10(followup[i]) > np.log10(max(followup)) - 1):
                plt.annotate(prefix,
                            (standalone[i], followup[i]),
                            xytext=(5, 5),
                            textcoords='offset points',
                            fontsize=8)

    # Customize plot with log scales
    # plt.xscale('log')
    # plt.yscale('log')
    plt.xlabel('Standalone Occurrences')
    plt.ylabel('Following Occurrences')
    plt.title('Prefix Usage Analysis: Standalone vs Following Occurrences')
    
    # Create a legend with threshold explanation
    handles, labels = plt.gca().get_legend_handles_labels()
    threshold_explanation = (
        'Threshold Formula:\n'
        '  1 if 3k ≤ x ≤ 5k\n'
        '  x/500 - 10 if 5k < x ≤ 20k\n'
        '  x/50 - 700 if x > 20k'
    )
    handles.append(Patch(color='none', label=threshold_explanation))
    
    plt.legend(handles=handles, bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, alpha=0.3, which='both')  # Add grid lines for both major and minor ticks

    # Set reasonable limits for log scales
    plt.xlim(left=0, right=200000)  # Start at 1 since log(0) is undefined
    plt.ylim(bottom=0, top=10000)  # Allow ratios below 1

    # Add some padding
    plt.margins(0.1)

    # Adjust layout
    plt.tight_layout()

    # Save plot
    plt.savefig(output_path, bbox_inches='tight', dpi=300)
    plt.close()
    
    print(f"Plot saved as: {output_path}")

# Example usage
if __name__ == "__main__":
    json_file = "../results/prefix_statistics.json"
    output_path = '../results/for_graph.png'
    visualize_occurrence_relationships(json_file, output_path)