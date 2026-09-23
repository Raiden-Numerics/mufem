import subprocess

# flake8: noqa: FKA100
from PIL import Image


def create_scene(index: int, rpm: int):

    import focus_viewer  # type: ignore[import-not-found]
    import os

    script_dir = os.path.dirname(os.path.abspath(__file__))

    data_file = f"{script_dir}/VisualizationOutput/Output_{index}.vtpc"

    viewer = focus_viewer.FocusViewer()
    viewer.initialize()
    viewer.load_data_file(str(data_file))
    viewer.reset_view()

    scene = viewer.get_active_scene()

    solid_visual = scene.new_solid_visual()

    for hide in [13, 12, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
        solid_visual.set_block_visibility(hide, False)

    solid_visual.set_color(205, 112, 43)  # Copper

    # Note that if we put this later it is influenced by the vectors reaching
    # out of the domain.
    viewer.get_camera().set_orientation(13)
    viewer.get_camera().fit_to_scene(0.7)

    # Show currents
    vector_visual = scene.new_vector_visual()
    vector_visual.set_vector_field("Electric Current Density")  # magnitude only

    for hide in [13, 12, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
        vector_visual.set_block_visibility(hide, False)

    vector_visual.set_scale_factor(5.0e-3)
    vector_visual.set_colorbar_visible(True)
    vector_visual.set_scalar_range(0, 5e7)

    vector_visual.set_arrow_tip_radius(0.19)
    vector_visual.set_arrow_shaft_radius(0.08)
    vector_visual.set_arrow_resolution(12, 12)

    # Show magnets

    scene_magnet_n = scene.new_solid_visual()
    for hide in [0, 1, 3, 5, 7, 9, 11, 12, 13]:
        scene_magnet_n.set_block_visibility(hide, False)

    scene_magnet_n.set_color(255, 0, 0)  # Red for N magnets

    scene_magnet_s = scene.new_solid_visual()
    for hide in [0, 2, 4, 6, 8, 10, 11, 12, 13]:
        scene_magnet_s.set_block_visibility(hide, False)

    scene_magnet_s.set_color(0, 0, 255)  # Blue for S magnets

    ann1 = scene.new_annotation_visual()
    ann1.set_text(f"RPM: {rpm:.0f}")
    ann1.set_position(0.2, 0.05)
    ann1.set_color(100, 100, 100)
    ann1.set_font_size(38)
    ann1.set_bold(True)

    viewer.save_screenshot(f"vis/Scene_Electric_Current_Density_{index:03d}.png")


def combine_images(large_path, small1_path, output_path, small_scale=0.9, right_padding=80):
    large = Image.open(large_path)
    small1 = Image.open(small1_path)

    large = large.crop((150, 0, large.width - 250, large.height))

    # resize small1 to match height, then scale down a bit
    ratio = large.height / small1.height
    new_w = int(small1.width * ratio * small_scale)
    new_h = int(small1.height * ratio * small_scale)
    small1 = small1.resize((new_w, new_h))

    # canvas: add padding on the far right; center small1 vertically
    total_width = large.width + new_w + right_padding
    total_height = large.height

    out = Image.new("RGB", (total_width, total_height), "white")

    out.paste(large, (0, 0))

    x = large.width  # start right after large
    y = (large.height - new_h) // 2
    out.paste(small1, (x, y))

    out = out.crop((100, 0, out.width - 100, out.height))

    out.save(output_path)


if __name__ == "__main__":
    # 90 is currently hard-coded to three rotation rates each for 30 time steps
    for i in range(90):
        rpm = [500, 1000, 2000][i // 30]

        create_scene(i, rpm)
        combine_images(
            large_path=f"vis/Scene_Electric_Current_Density_{i:03d}.png",
            small1_path=f"vis/Torque_vs_RPM_{i:03d}.png",
            output_path=f"vis/Scene_{i:03d}.png",
        )

    # 1) Use ffmpeg to convert the images to an animated gif

    commands = [
        (
            "ffmpeg -framerate 8 -i vis/Scene_%03d.png "
            '-vf "pad=ceil(iw/2)*2:ceil(ih/2)*2" -c:v libx264 -pix_fmt yuv420p vis/output.mp4'
        ),
        (
            "ffmpeg -i vis/output.mp4 "
            "-vf 'fps=8,scale=800:-1:flags=lanczos' "
            "-c:v gif results/Result_Animation.gif -y"
        ),
    ]
    for command in commands:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)

        if result.returncode != 0:
            print(result.stderr)
